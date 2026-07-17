"""
rssi_xgb_rsu/predict.py — label-free RSU-tier RSSI XGBoost inference (v2, honest),
producing p̄_rssi for the Eq 3.20 ensemble (Phase 1, RSU tier).

Reproduces RSSI_Model2_XGBoost_RSU_v2.ipynb's honest (leakage-free) feature extraction
VERBATIM (10 sentinel-safe RSSI + RSU-geometry features over 5 s / 2 s windows), minus
the training-only coupling (manifest subsample, phase labels, split). Loads the saved
model — never refits:
    outputs/rssi_xgb_honest.pkl            (XGBClassifier, 7-class)
    outputs/rssi_xgb_honest_features.pkl   (feature order)

Input = rssi_verification_log. Sentinel: rssi_dbm == 40.0 (no valid measurement) is
excluded from RSSI aggregates; its rate is the honest `valid_rate` feature. p̄_rssi =
1 − P(legit). Windows are floored to the 2 s grid; snap + mean-pool defensively.

API:
  p = RSSIXGBPredictor.load()
  df = p.score_logs(run_dir, t=None, run_id="live")  # -> run_id, claimed_node_id,
       window_start_seconds, p_bar_rssi, p_rssi_0..6
"""

import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1] / "fusion"))
import identity_manifest as IDM          # noqa: E402  (snap_grid)

MODEL_PKL = _HERE / "outputs" / "rssi_xgb_honest.pkl"
FEATURES_PKL = _HERE / "outputs" / "rssi_xgb_honest_features.pkl"
N_CLASSES, LEGIT = 7, 0
WINDOW_SEC, STEP_SEC = 5.0, 2.0
RSSI_SENTINEL, RSSI_FILL = 40.0, -100.0

RSSI_USE = ["time", "observer_vehicle_id", "observed_claimed_id", "observed_real_id",
            "rssi_dbm", "rssi_estimated_distance_m", "claimed_distance_m"]
DEDUP = ["time", "observer_vehicle_id", "observed_claimed_id", "observed_real_id", "rssi_dbm"]


def full_proba(model, X):
    p = model.predict_proba(X)
    full = np.zeros((len(X), N_CLASSES), dtype=np.float32)
    for j, c in enumerate(model.classes_):
        full[:, int(c)] = p[:, j]
    return full


def build_rsu_features(df, run_id, window_sec=WINDOW_SEC, step_sec=STEP_SEC):
    """VERBATIM honest feature builder (label-free: attack_type set to a dummy 0)."""
    records = []
    for cid, grp in df.groupby("observed_claimed_id", sort=False):
        grp = grp.sort_values("time")
        t_arr = grp["time"].values.astype(float)
        rssi = grp["rssi_dbm"].values.astype(float)
        valid = grp["valid"].values
        d_cl = np.maximum(grp["claimed_distance_m"].values.astype(float), 1.0)
        obs = grp["observer_vehicle_id"].values
        t = np.floor(t_arr.min() / step_sec) * step_sec
        tmax = t_arr.max()
        while t < tmax:
            m = (t_arr >= t) & (t_arr < t + window_sec)
            ntot = int(m.sum())
            if ntot < 2:
                t += step_sec
                continue
            vm = m & valid
            nv = int(vm.sum())
            rv = rssi[vm]
            nobs = int(pd.unique(obs[m]).size)
            records.append({
                "run_id": run_id, "claimed_node_id": int(cid),
                "window_start_seconds": float(t),
                "valid_rate": nv / ntot,
                "rssi_mean": float(rv.mean()) if nv else RSSI_FILL,
                "rssi_std": float(rv.std()) if nv > 1 else 0.0,
                "rssi_min": float(rv.min()) if nv else RSSI_FILL,
                "rssi_max": float(rv.max()) if nv else RSSI_FILL,
                "observer_count": nobs,
                "n_beacons": ntot,
                "beacons_per_observer": ntot / max(nobs, 1),
                "claimed_dist_mean": float(d_cl[m].mean()),
                "claimed_dist_std": float(d_cl[m].std()),
            })
            t += step_sec
    return pd.DataFrame(records)


def build_features_live(run_dir, t=None, run_id="live", nrows=None, rows=None):
    """`rows`: pre-read rssi-log DataFrame already filtered to <= t (daemon LogCache
    fast path); when given, the CSV read is skipped."""
    if rows is not None:
        df = rows.copy()
    else:
        df = pd.read_csv(Path(run_dir) / "rssi_verification_log.csv",
                         usecols=lambda c: c in set(RSSI_USE), nrows=nrows)
        if t is not None:
            df = df[df["time"] <= float(t)]
    if df.empty:
        return pd.DataFrame()
    df = df.drop_duplicates(subset=DEDUP)
    df["valid"] = (df["rssi_dbm"].values != RSSI_SENTINEL) & \
                  (df["rssi_estimated_distance_m"].values > 0)
    return build_rsu_features(df, run_id)


class RSSIXGBPredictor:
    def __init__(self, model, features):
        self.model = model
        self.features = features

    @classmethod
    def load(cls, model_pkl=MODEL_PKL, features_pkl=FEATURES_PKL):
        return cls(joblib.load(model_pkl), joblib.load(features_pkl))

    def score_logs(self, run_dir, t=None, run_id="live", nrows=None, rows=None):
        fdf = build_features_live(run_dir, t=t, run_id=run_id, nrows=nrows, rows=rows)
        if fdf is None or fdf.empty:
            return pd.DataFrame()
        fdf = fdf.copy()
        fdf["window_start_seconds"] = IDM.snap_grid(fdf["window_start_seconds"].to_numpy())
        fp = full_proba(self.model, fdf[self.features])
        out = fdf[["run_id", "claimed_node_id", "window_start_seconds"]].copy()
        out["p_bar_rssi"] = (1.0 - fp[:, LEGIT]).astype(np.float32)
        for k in range(N_CLASSES):
            out[f"p_rssi_{k}"] = fp[:, k].astype(np.float32)
        key = ["run_id", "claimed_node_id", "window_start_seconds"]
        val = ["p_bar_rssi"] + [f"p_rssi_{k}" for k in range(N_CLASSES)]
        return out.groupby(key, as_index=False)[val].mean()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--t", type=float, default=None)
    ap.add_argument("--run-id", default="live")
    ap.add_argument("--nrows", type=int, default=None)
    args = ap.parse_args()
    p = RSSIXGBPredictor.load()
    df = p.score_logs(args.run_dir, t=args.t, run_id=args.run_id, nrows=args.nrows)
    print(f"scored {len(df):,} rows")
    if len(df):
        print("cols:", list(df.columns))
        print("p_bar_rssi range: [%.3f, %.3f] mean=%.3f" % (
            df.p_bar_rssi.min(), df.p_bar_rssi.max(), df.p_bar_rssi.mean()))
        print(df.head(3).to_string())
