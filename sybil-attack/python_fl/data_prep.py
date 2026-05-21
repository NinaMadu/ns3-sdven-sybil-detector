"""
data_prep.py — FLEMDS dataset loader and pre-processor.

Reads the fl_dataset.csv produced by the ns-3 simulation and prepares
time-series sequences for the on-vehicle LSTM model.

Binary label contract (matches C++ logger):
    attack_type_raw == 0  OR  IsSybilVehicle == False  →  sybil_label = 0  (Normal)
    any attack type 1-6   AND IsSybilVehicle == True   →  sybil_label = 1  (Sybil)

The column 'sybil_label' in the CSV is already binary; this module verifies
and exposes it without re-deriving from attack_type_raw.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

# Features fed into the LSTM (BSM time-series + resource metrics)
FEATURE_COLS: List[str] = [
    "pos_x", "pos_y",
    "speed", "heading", "acceleration",
    "beacons_sent", "beacons_recv",
    "rssi_avg_dbm", "rssi_std_dbm",
    "dist_mismatch_avg", "dist_mismatch_count",
    "neighbor_count", "id_change_count",
    "residual_energy_pct", "memory_free_pct", "data_quality",
    "trust_score",
]

# FLBFLVS client-selection metrics (subset of FEATURE_COLS)
FLBFLVS_COLS: List[str] = [
    "rssi_avg_dbm",
    "residual_energy_pct",
    "memory_free_pct",
    "data_quality",
]

TARGET_COL = "sybil_label"
VEHICLE_ID_COL = "vehicle_id"
TIME_COL = "sim_time"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load the fl_dataset.csv and return a clean DataFrame."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Dataset not found: {csv_path}\n"
            "Run the ns-3 simulation first:\n"
            "  cd ns-allinone-3.35/ns-3.35\n"
            "  ./waf --run 'Sybil-Developing-Improved "
            "--config=sybil-attack/configs/sybil_fl_detection.cfg'"
        )

    df = pd.read_csv(csv_path)

    # Ensure binary label column is integer
    df[TARGET_COL] = df[TARGET_COL].astype(int)

    # Sort by vehicle then time for correct sequence construction
    df = df.sort_values([VEHICLE_ID_COL, TIME_COL]).reset_index(drop=True)

    # Fill any NaN (e.g. first-step acceleration) with 0
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(0.0)

    return df


def print_class_distribution(df: pd.DataFrame) -> None:
    total = len(df)
    sybil = df[TARGET_COL].sum()
    normal = total - sybil
    print(f"Dataset rows : {total}")
    print(f"  Normal (0) : {normal}  ({100.0*normal/total:.1f}%)")
    print(f"  Sybil  (1) : {sybil}  ({100.0*sybil/total:.1f}%)")
    print(f"  Vehicles   : {df[VEHICLE_ID_COL].nunique()}")
    print(f"  Time steps : {df[TIME_COL].nunique()}")


def fit_scaler(df: pd.DataFrame) -> StandardScaler:
    """Fit a StandardScaler on the training data's feature columns."""
    scaler = StandardScaler()
    scaler.fit(df[FEATURE_COLS])
    return scaler


def apply_scaler(df: pd.DataFrame, scaler: StandardScaler) -> pd.DataFrame:
    """Return a copy of df with FEATURE_COLS normalised."""
    df = df.copy()
    df[FEATURE_COLS] = scaler.transform(df[FEATURE_COLS])
    return df


def make_sequences(
    vehicle_df: pd.DataFrame,
    seq_len: int = 10,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build overlapping time-series windows for a single vehicle.

    Parameters
    ----------
    vehicle_df : rows for ONE vehicle, ordered by sim_time
    seq_len    : window length T (default 10 seconds)

    Returns
    -------
    X : shape (N_windows, seq_len, n_features)  float32
    y : shape (N_windows,)                       int32
        Label is the sybil_label of the LAST timestep in each window.
    """
    feats = vehicle_df[FEATURE_COLS].values.astype(np.float32)
    labels = vehicle_df[TARGET_COL].values.astype(np.int32)

    n = len(feats)
    if n < seq_len:
        # Pad with the first row if the vehicle has fewer timesteps than seq_len
        pad_rows = seq_len - n
        feats = np.vstack([np.tile(feats[0], (pad_rows, 1)), feats])
        labels = np.concatenate([np.full(pad_rows, labels[0], dtype=np.int32), labels])
        n = seq_len

    X, y = [], []
    for i in range(n - seq_len + 1):
        X.append(feats[i : i + seq_len])
        y.append(labels[i + seq_len - 1])
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def build_all_sequences(
    df: pd.DataFrame,
    seq_len: int = 10,
) -> Tuple[Dict[int, Tuple[np.ndarray, np.ndarray]], List[int]]:
    """
    Build sequences for every vehicle.

    Returns
    -------
    seqs      : {vehicle_id: (X, y)}
    vehicle_ids : sorted list of vehicle IDs that have data
    """
    seqs: Dict[int, Tuple[np.ndarray, np.ndarray]] = {}
    for vid, vdf in df.groupby(VEHICLE_ID_COL):
        X, y = make_sequences(vdf, seq_len)
        if len(X) > 0:
            seqs[int(vid)] = (X, y)
    return seqs, sorted(seqs.keys())


def get_flbflvs_metrics(df: pd.DataFrame) -> Dict[int, Dict[str, float]]:
    """
    Extract the LATEST FLBFLVS metric snapshot per vehicle.

    Returns {vehicle_id: {rssi_avg_dbm, residual_energy_pct,
                           memory_free_pct, data_quality}}
    """
    latest = df.sort_values(TIME_COL).groupby(VEHICLE_ID_COL).last().reset_index()
    metrics: Dict[int, Dict[str, float]] = {}
    for _, row in latest.iterrows():
        vid = int(row[VEHICLE_ID_COL])
        metrics[vid] = {col: float(row[col]) for col in FLBFLVS_COLS}
    return metrics


def assign_vehicles_to_rsus(
    df: pd.DataFrame,
    rsu_x_positions: List[float],
) -> Dict[int, int]:
    """
    Assign each vehicle to the closest RSU (by mean pos_x over all timesteps).

    Parameters
    ----------
    rsu_x_positions : list of RSU x-coordinates in metres,
                      e.g. [200.0, 600.0] for 2 RSUs spaced along the road.

    Returns
    -------
    {vehicle_id: rsu_index}
    """
    mean_pos = df.groupby(VEHICLE_ID_COL)["pos_x"].mean()
    assignments: Dict[int, int] = {}
    for vid, mean_x in mean_pos.items():
        dists = [abs(mean_x - rx) for rx in rsu_x_positions]
        assignments[int(vid)] = int(np.argmin(dists))
    return assignments


def train_val_split(
    seqs: Dict[int, Tuple[np.ndarray, np.ndarray]],
    val_fraction: float = 0.2,
) -> Tuple[Dict[int, Tuple[np.ndarray, np.ndarray]],
           Dict[int, Tuple[np.ndarray, np.ndarray]]]:
    """
    Temporal split: last val_fraction of each vehicle's sequences → validation.
    """
    train, val = {}, {}
    for vid, (X, y) in seqs.items():
        n = len(X)
        split = max(1, int(n * (1 - val_fraction)))
        train[vid] = (X[:split], y[:split])
        val[vid]   = (X[split:], y[split:])
    return train, val
