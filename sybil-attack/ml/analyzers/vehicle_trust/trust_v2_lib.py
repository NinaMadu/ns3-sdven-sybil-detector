"""
Vehicle-Tier Trust Analyzer v2 — enriched, multi-percentage, paper-aligned.

Reuses the validated v1 trust math (Φ_coloc Eq 3.3, IAT entropy Eq 3.4, the
closed-form T/T_hist resolution Eqs 3.22-3.25, the compact MLP φ_trust, and the
hierarchical FedProx+DP+trimmed-mean FL Eqs 3.26-3.28) and ENRICHES it with the
observable signals the v1 notebook never touched (verified in the data):

  • RSSI verification  — verification_state / mismatch_m  (MISMATCH ≈ 98.6% sybil)
  • Identity lifetime  — last_seen−first_seen            (legit 6.5s vs sybil 3.0s)
  • Beacon persistence — received_beacon_count
  • Cross-tier consensus — RSU regional awareness (observer_count, report_count,
    rssi_verified_probability, rssi_false_data_decision) + controller trust_score
    — a genuinely INDEPENDENT vantage feeding T_hist / reputation.

Trained on a real attacker-percentage sweep (pct20 + pct40 + pct100) so a true
legitimate class exists (v1's missing-200-veh-sweep, mismatch #4). 7-class
aligned: exports attack_type∈{0..6}, is_sybil∈{0,1}, keyed
(claimed_node_id, window_start_seconds, split) per the pipeline data contract.

The analytic T_RSSI/T_behav/T_hist keep their paper equations UNCHANGED; the
enrichment goes into (a) the MLP feature vector that produces φ_trust (the
deployed trust score the LLM reads) and (b) T_hist's reputation prior via the
cross-tier consensus. No thesis equation is rewritten.

Runs in ml/.venv (pandas/numpy/torch). Memory-safe: one run loaded at a time,
aggregated to windows, then concatenated.
"""

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

RNG_SEED = 7
rng = np.random.default_rng(RNG_SEED)
np.random.seed(RNG_SEED)
torch.manual_seed(RNG_SEED)

_HERE = Path(__file__).resolve().parent
DATA_ROOT = (_HERE / ".." / ".." / "datasets").resolve()

# ── Shared fusion spine (single source of truth for identity subsample + split +
#    2 s export grid). Makes trust align with RSSI & GRU so the phi tables join. ──
import sys as _sys
_sys.path.insert(0, str(_HERE.parent / "fusion"))
import identity_manifest as IDM
ARTIFACTS_DIR = IDM.ARTIFACTS_DIR
_MAN = None
def shared_manifest():
    global _MAN
    if _MAN is None:
        _MAN = IDM.load_manifest()
    return _MAN

# ── The three focus runs (from the shared spine) ────────────────────────────
DATASETS = [Path(d) for d in IDM.RUN_DIRS]

# ── 7-class taxonomy (pipeline contract) ────────────────────────────────────
CLASS_NAMES = {0: "legitimate", 1: "outsider", 2: "sim", 3: "nonsim",
               4: "indirect", 5: "malicious_rsu", 6: "malicious_controller"}

# ── suspicion_flags bits (docs/DETECTION_FLAGS_REPORT.md) ───────────────────
SUSP_RANGE_ANOMALY          = 1 << 3
SUSP_RSSI_COLOCATION        = 1 << 5
SUSP_TRAJECTORY_SHADOWING   = 1 << 6
SUSP_RSSI_DISTANCE_MISMATCH = 1 << 8
SUSP_INVALID_V2V_SIGNATURE  = 1 << 9

NEIGHBOR_LOG   = "vehicle_neighbor_table_log.csv"
RSSI_LOG       = "rssi_verification_log.csv"
RSU_HIER_LOG   = "rsu_vehicle_observation_rows_log.csv"
RSU_AWARE_LOG  = "rsu_regional_awareness_log.csv"
CTRL_AWARE_LOG = "controller_global_awareness_log.csv"

NEIGHBOR_COLS = {
    "time", "observer_vehicle_id", "observed_real_id", "observed_claimed_id",
    "bsm_x", "bsm_y", "bsm_speed", "bsm_heading", "estimated_distance",
    "received_beacon_count", "suspicion_flags", "first_seen_time", "last_seen_time",
    "traj_shadow_score", "traj_shadow_compared",
}
RSSI_COLS = {
    "time", "observer_vehicle_id", "observed_claimed_id", "observed_real_id",
    "rssi_dbm", "mismatch_m", "verification_state", "claimed_distance_m",
    "rssi_estimated_distance_m",
}

R_NOM_DEFAULT = 10.0
IAT_ENTROPY_BINS = 5

# Intensity ladder (mode-9 stepped schedule) — used ONLY to annotate windows with
# active_attack_pct as EVAL-ONLY METADATA. It is NOT a model feature: a real vehicle
# cannot observe the attack density; using it as an input would be oracle leakage.
# It exists so detection can be *analysed/stratified* by attack intensity.
INTENSITY_LADDER = [20, 40, 60, 80, 100]
N_SUBWINDOWS = 5


def compute_active_attack_pct(times, phase_duration, ladder=INTENSITY_LADDER, n_sub=N_SUBWINDOWS):
    """Deterministic active-attacker % at time t (verified 100% vs the logged column):
    ladder[floor((t mod phase_duration) / (phase_duration/n_sub))]."""
    t = np.asarray(times, dtype=float)
    sw_dur = phase_duration / n_sub
    phase_t = t - (t // phase_duration) * phase_duration
    sw = np.clip((phase_t // sw_dur).astype(int), 0, n_sub - 1)
    return np.asarray(ladder)[sw]


# ═══════════════════════════════════════════════════════════════════════════
# 1. Phase → attack-type labelling
# ═══════════════════════════════════════════════════════════════════════════
def load_phase_table(dataset_dir: Path) -> pd.DataFrame:
    cands = sorted(dataset_dir.glob("attack_phases_*.csv"))
    if not cands:
        raise FileNotFoundError(f"no attack_phases_*.csv in {dataset_dir}")
    return pd.read_csv(cands[0]).sort_values("start_time").reset_index(drop=True)


def assign_attack_type(times, phase_df: pd.DataFrame) -> np.ndarray:
    starts = phase_df["start_time"].to_numpy(dtype=float)
    types = phase_df["attack_type"].to_numpy()
    t = np.asarray(times, dtype=float)
    idx = np.searchsorted(starts, t, side="right") - 1
    out = np.zeros(len(t), dtype=np.int64)
    valid = idx >= 0
    out[valid] = types[idx[valid]]
    return out


# ═══════════════════════════════════════════════════════════════════════════
# 2. Enriched per-run loader  (neighbor ⋈ rssi-verify ⋈ RSU/controller consensus)
# ═══════════════════════════════════════════════════════════════════════════
def _decompose_suspicion(neighbor: pd.DataFrame) -> pd.DataFrame:
    flags = neighbor["suspicion_flags"].fillna(0).astype("int64")
    neighbor["range_anomaly"]          = ((flags & SUSP_RANGE_ANOMALY) != 0).astype("int8")
    neighbor["rssi_distance_mismatch"] = ((flags & SUSP_RSSI_DISTANCE_MISMATCH) != 0).astype("int8")
    neighbor["rssi_colocation"]        = ((flags & SUSP_RSSI_COLOCATION) != 0).astype("int8")
    neighbor["trajectory_shadowing"]   = ((flags & SUSP_TRAJECTORY_SHADOWING) != 0).astype("int8")
    for c in ("traj_shadow_score", "traj_shadow_compared"):
        if c not in neighbor.columns:
            neighbor[c] = 0.0
    neighbor["traj_shadow_score"]    = neighbor["traj_shadow_score"].fillna(0.0).astype("float32")
    neighbor["traj_shadow_compared"] = neighbor["traj_shadow_compared"].fillna(0).astype("int8")
    return neighbor


def load_vehicle_to_rsu(dataset_dir: Path) -> Dict[int, int]:
    path = dataset_dir / RSU_HIER_LOG
    if not path.exists():
        return {}
    try:
        f = pd.read_csv(path, usecols=["rsu_id", "reported_by_vehicle_id"])
    except Exception:
        return {}
    f = f.dropna(subset=["rsu_id", "reported_by_vehicle_id"])
    m: Dict[int, int] = {}
    for vid, rid in zip(f["reported_by_vehicle_id"], f["rsu_id"]):
        m.setdefault(int(vid), int(rid))
    return m


def load_consensus(dataset_dir: Path) -> pd.DataFrame:
    """RSU regional + controller global awareness, per (claimed_id, time).
    Tiny aggregated logs — the independent cross-tier reputation vantage."""
    frames = []
    ra = dataset_dir / RSU_AWARE_LOG
    if ra.exists():
        d = pd.read_csv(ra, usecols=lambda c: c in {
            "time", "claimed_vehicle_id", "observer_count", "report_count",
            "rssi_verified_probability", "rssi_false_data_decision"})
        d = d.rename(columns={"claimed_vehicle_id": "observed_claimed_id",
                              "observer_count": "rsu_observer_count",
                              "report_count": "rsu_report_count",
                              "rssi_verified_probability": "rsu_verified_prob",
                              "rssi_false_data_decision": "rsu_false_decision"})
        frames.append(("rsu", d))
    ca = dataset_dir / CTRL_AWARE_LOG
    if ca.exists():
        d = pd.read_csv(ca, usecols=lambda c: c in {
            "time", "claimed_vehicle_id", "trust_score", "observer_count"})
        d = d.rename(columns={"claimed_vehicle_id": "observed_claimed_id",
                              "trust_score": "ctrl_trust",
                              "observer_count": "ctrl_observer_count"})
        frames.append(("ctrl", d))
    return frames


def build_run_windows(dataset_dir: Path, subsample_frac: float, window_w: int,
                      hp: dict) -> pd.DataFrame:
    """Load ONE run, enrich, and aggregate straight to windows (memory-safe)."""
    meta = json.loads((dataset_dir / "run_meta.json").read_text())
    phase_df = load_phase_table(dataset_dir)
    pct = int(meta.get("sybil_attack_percentage", 0))
    base = f"{meta.get('run_id', dataset_dir.name)}"

    # Memory-safe: stream the ~6 GB neighbor log in chunks, keeping ONLY the shared
    # identity subsample (same claimed ids as RSSI & GRU) — the full file is never held
    # in RAM. Replaces the old full-read + per-observer random subsample.
    neighbor = IDM.read_run_log_filtered(
        dataset_dir / NEIGHBOR_LOG, (lambda c: c in NEIGHBOR_COLS),
        "observed_claimed_id", base, shared_manifest())
    neighbor["phase_type"] = assign_attack_type(neighbor["time"].to_numpy(), phase_df)
    neighbor = neighbor[neighbor["phase_type"] > 0].copy()

    for c in ("bsm_x", "bsm_y", "bsm_speed", "bsm_heading", "estimated_distance",
              "first_seen_time", "last_seen_time"):
        if c in neighbor:
            neighbor[c] = neighbor[c].astype("float32")
    for c in ("observer_vehicle_id", "observed_real_id", "observed_claimed_id",
              "received_beacon_count"):
        neighbor[c] = neighbor[c].astype("int64")

    neighbor = _decompose_suspicion(neighbor)
    neighbor["is_sybil"] = (neighbor["observed_real_id"] != neighbor["observed_claimed_id"]).astype(int)
    neighbor["token_valid"] = (
        (neighbor["suspicion_flags"].fillna(0).astype("int64") & SUSP_INVALID_V2V_SIGNATURE) == 0
    ).astype(int)
    # 7-class label: attack type only where the identity is actually spoofed
    neighbor["attack_type"] = np.where(neighbor["is_sybil"] == 1, neighbor["phase_type"], 0).astype("int64")

    # ── enriched RSSI verification join (as-of, per observer+claimed) ────────
    rssi_path = dataset_dir / RSSI_LOG
    if rssi_path.exists() and rssi_path.stat().st_size > 100:
        # stream the ~3 GB rssi log, keep only the shared subsample's rows
        rssi = IDM.read_run_log_filtered(
            rssi_path, (lambda c: c in RSSI_COLS),
            "observed_claimed_id", base, shared_manifest())
        rssi = rssi.dropna(subset=["time", "observer_vehicle_id", "observed_claimed_id"])
        rssi["observer_vehicle_id"] = rssi["observer_vehicle_id"].astype("int64")
        rssi["observed_claimed_id"] = rssi["observed_claimed_id"].astype("int64")
        rssi["rssi_dbm"] = rssi["rssi_dbm"].astype("float32")
        rssi["mismatch_m"] = pd.to_numeric(rssi.get("mismatch_m"), errors="coerce").astype("float32")
        rssi["rssi_mismatch_flag"] = (rssi.get("verification_state") == "MISMATCH").astype("int8")
        keep_rssi = ["time", "observer_vehicle_id", "observed_claimed_id",
                     "rssi_dbm", "mismatch_m", "rssi_mismatch_flag"]
        rssi["time"] = rssi["time"].astype("float64")
        neighbor["time"] = neighbor["time"].astype("float64")
        neighbor = neighbor.sort_values("time")
        rssi = rssi.sort_values("time")
        neighbor = pd.merge_asof(
            neighbor, rssi[keep_rssi], on="time",
            by=["observer_vehicle_id", "observed_claimed_id"],
            direction="nearest", tolerance=0.5)
        neighbor["rssi_mismatch_flag"] = neighbor["rssi_mismatch_flag"].fillna(0).astype("int8")
        del rssi
    else:
        neighbor["rssi_dbm"] = np.float32(np.nan)
        neighbor["mismatch_m"] = np.float32(np.nan)
        neighbor["rssi_mismatch_flag"] = np.int8(0)

    # ── cross-tier consensus join (tiny logs; as-of per claimed_id) ─────────
    for tier, cdf in load_consensus(dataset_dir):
        cdf = cdf.dropna(subset=["time", "observed_claimed_id"]).sort_values("time").copy()
        cdf["observed_claimed_id"] = cdf["observed_claimed_id"].astype("int64")
        cdf["time"] = cdf["time"].astype("float64")
        neighbor["time"] = neighbor["time"].astype("float64")
        neighbor["observed_claimed_id"] = neighbor["observed_claimed_id"].astype("int64")
        # consensus logs are sparse/aggregated — carry the last known report forward
        # per claimed id (a claimed id's RSU/controller reputation persists).
        neighbor = pd.merge_asof(
            neighbor.sort_values("time"), cdf, on="time",
            by="observed_claimed_id", direction="backward", tolerance=30.0)

    vmap = load_vehicle_to_rsu(dataset_dir)
    neighbor["rsu_id"] = neighbor["observer_vehicle_id"].map(vmap).fillna(-1).astype(int)
    neighbor["run_id"] = base + "_type" + neighbor["attack_type"].astype(str)
    neighbor["attack_percentage"] = pct

    w = _aggregate_windows(neighbor, window_w)
    del neighbor
    w = add_coloc_features(w, hp["sigma_ch"], hp["gamma_co"])
    w = add_trust_scores(w, hp["alpha"], hp["beta"], hp["gamma"], hp["lam"], hp["mu"])
    # EVAL-ONLY metadata: attack intensity at each window (NOT a feature — see note above)
    phase_dur = float(meta.get("sim_time_per_phase", 48))
    w["active_attack_pct"] = compute_active_attack_pct(
        (w["window_start"] + w["window_end"]) / 2.0, phase_dur)
    return w


# ═══════════════════════════════════════════════════════════════════════════
# 3. Trust math  (Eqs 3.3-3.5, 3.22-3.25) — reused, windows now carry more cols
# ═══════════════════════════════════════════════════════════════════════════
def phi_coloc(rssi_a, rssi_b, sigma_ch):
    if not (np.isfinite(rssi_a) and np.isfinite(rssi_b)):
        return 0.0
    return float(np.exp(-((rssi_a - rssi_b) ** 2) / (2.0 * sigma_ch ** 2)))


def iat_entropy(times, r_nom=R_NOM_DEFAULT, n_bins=IAT_ENTROPY_BINS):
    if len(times) < 3:
        return np.nan
    iat = np.diff(np.sort(times))
    iat = iat[iat >= 0]
    if len(iat) < 2:
        return np.nan
    edges = np.linspace(0.0, 3.0 / r_nom, n_bins + 1)
    edges[-1] = np.inf
    counts, _ = np.histogram(iat, bins=edges)
    tot = counts.sum()
    if tot == 0:
        return np.nan
    p = counts[counts > 0] / tot
    return float(-(p * np.log2(p)).sum())


def _first_mode(s):
    m = s.mode()
    return m.iloc[0] if len(m) else np.nan


def _aggregate_windows(df: pd.DataFrame, window: int) -> pd.DataFrame:
    """Tumbling W-beacon windows per (run_id, observer, claimed_id). window_start
    is in SECONDS (data contract). Aggregates the enriched signals."""
    rows = []
    min_dur = 0.5 / R_NOM_DEFAULT
    gcols = ["run_id", "observer_vehicle_id", "observed_claimed_id"]
    has_life = {"first_seen_time", "last_seen_time"}.issubset(df.columns)
    for key, g in df.groupby(gcols, sort=False):
        g = g.sort_values("time")
        n = len(g)
        for start in range(0, n, window):
            c = g.iloc[start:start + window]
            if len(c) < 1:
                continue
            dur = max(c["time"].iloc[-1] - c["time"].iloc[0], min_dur)
            brate = (len(c) - 1) / dur if len(c) > 1 else 0.0
            traj = c.loc[c["traj_shadow_compared"] == 1, "traj_shadow_score"]
            life = (float(c["last_seen_time"].max() - c["first_seen_time"].min())
                    if has_life else np.nan)
            rows.append({
                "run_id": key[0], "observer_vehicle_id": key[1], "observed_claimed_id": key[2],
                "observed_real_id": _first_mode(c["observed_real_id"]),
                "window_start": float(c["time"].iloc[0]), "window_end": float(c["time"].iloc[-1]),
                "n_beacons": len(c), "n_beacons_norm": len(c) / window, "beacon_rate": brate,
                "rssi_mean": c["rssi_dbm"].mean(),
                # enriched RSSI verification
                "rssi_mismatch_frac": float(c["rssi_mismatch_flag"].mean()),
                "mismatch_m_mean": float(np.nanmean(c["mismatch_m"])) if c["mismatch_m"].notna().any() else 0.0,
                # enriched persistence
                "identity_lifetime": life if np.isfinite(life) else 0.0,
                "beacon_count_mean": float(c["received_beacon_count"].mean()),
                # enriched cross-tier consensus (nan-safe means)
                "rsu_observer_count": float(np.nanmean(c["rsu_observer_count"])) if "rsu_observer_count" in c and c["rsu_observer_count"].notna().any() else 0.0,
                "rsu_report_count": float(np.nanmean(c["rsu_report_count"])) if "rsu_report_count" in c and c["rsu_report_count"].notna().any() else 0.0,
                "rsu_verified_prob": float(np.nanmean(c["rsu_verified_prob"])) if "rsu_verified_prob" in c and c["rsu_verified_prob"].notna().any() else 0.5,
                "rsu_false_decision": float(np.nanmax(c["rsu_false_decision"])) if "rsu_false_decision" in c and c["rsu_false_decision"].notna().any() else 0.0,
                "ctrl_trust": float(np.nanmean(c["ctrl_trust"])) if "ctrl_trust" in c and c["ctrl_trust"].notna().any() else 1.0,
                "ctrl_observer_count": float(np.nanmean(c["ctrl_observer_count"])) if "ctrl_observer_count" in c and c["ctrl_observer_count"].notna().any() else 0.0,
                # signatures / flags
                "token_valid": int(_first_mode(c["token_valid"])),
                "any_suspicion": int((c["suspicion_flags"].astype(int) != 0).any()),
                "range_anomaly": int(c["range_anomaly"].any()),
                "rssi_distance_mismatch": int(c["rssi_distance_mismatch"].any()),
                "rssi_colocation": int(c["rssi_colocation"].any()),
                "trajectory_shadowing": int(c["trajectory_shadowing"].any()),
                "traj_shadow_score": float(traj.mean()) if len(traj) else 0.0,
                "traj_shadow_compared": int(c["traj_shadow_compared"].any()),
                "iat_entropy": iat_entropy(c["time"].to_numpy()),
                "label": int(c["is_sybil"].max()),
                "attack_type": int(c["attack_type"].iloc[0]) if int(c["is_sybil"].max()) else 0,
                "rsu_id": int(_first_mode(c["rsu_id"])), "controller_id": 0,
                "attack_percentage": int(c["attack_percentage"].iloc[0]),
            })
    return pd.DataFrame(rows)


def add_coloc_features(w, sigma_ch, gamma_co):
    w = w.copy()
    cm = np.zeros(len(w)); cx = np.zeros(len(w)); had = np.zeros(len(w), int)
    for _, idx in w.groupby(["run_id", "observer_vehicle_id"]).groups.items():
        sub = w.loc[idx]
        if len(sub) < 2:
            continue
        s = sub["window_start"].to_numpy(); e = sub["window_end"].to_numpy()
        r = sub["rssi_mean"].to_numpy(); li = sub.index.to_numpy()
        for a in range(len(sub)):
            ov = (s <= e[a]) & (e >= s[a]); ov[a] = False
            if not ov.any():
                continue
            sims = [phi_coloc(r[a], r[b], sigma_ch) for b in np.nonzero(ov)[0]]
            cm[li[a]] = float(np.mean(sims)); cx[li[a]] = float(np.max(sims)); had[li[a]] = 1
    w["raw_coloc_mean"] = cm; w["raw_coloc_max"] = cx
    w["coloc_flag"] = (w["raw_coloc_max"] > gamma_co).astype(int)
    w["had_coloc_observation"] = had
    return w


def add_trust_scores(w, alpha, beta, gamma, lam, mu, r_nom=R_NOM_DEFAULT):
    assert abs(alpha + beta + gamma - 1.0) < 1e-6
    w = w.sort_values(["run_id", "observer_vehicle_id", "observed_claimed_id", "window_start"]).copy()
    w["raw_rate_deviation"] = (w["beacon_rate"] - r_nom).abs() / r_nom
    w["T_behav"] = np.exp(-lam * w["raw_rate_deviation"])
    w["T_RSSI"] = np.where(w["had_coloc_observation"] == 1, 1.0 - w["raw_coloc_mean"], 0.5)

    # T_hist reputation prior blended with the cross-tier consensus verified prob
    # (independent RSU vantage). Paper Eq 3.25 recursion is unchanged; the prior it
    # starts from is informed by consensus instead of a flat 0.5, so reputation is
    # grounded in the RSU/controller view rather than a single observer's history.
    T_hist = np.zeros(len(w)); T_comp = np.zeros(len(w))
    denom = 1.0 - gamma * (1.0 - mu)
    prev: Dict[Tuple, float] = {}
    rsu_vp = w["rsu_verified_prob"].to_numpy() if "rsu_verified_prob" in w else np.full(len(w), 0.5)
    for pos, (_, row) in enumerate(w.iterrows()):
        k = (row["run_id"], row["observer_vehicle_id"], row["observed_claimed_id"])
        vp = rsu_vp[pos]
        boot = vp if np.isfinite(vp) else 0.5           # consensus-grounded prior
        t_prev = prev.get(k, boot)
        t_now = (alpha * row["T_RSSI"] + beta * row["T_behav"] + gamma * mu * t_prev) / denom
        t_now = float(np.clip(t_now, 0.0, 1.0))
        h_now = mu * t_prev + (1.0 - mu) * t_now
        T_comp[pos] = t_now; T_hist[pos] = float(np.clip(h_now, 0.0, 1.0))
        prev[k] = t_now
    w["T_hist"] = T_hist; w["T_composite"] = T_comp
    return w.reset_index(drop=True)


# Enriched feature vector: v1's 16 + the new observable signals.
FEATURE_COLS = [
    "T_RSSI", "T_behav", "T_hist", "T_composite",
    "token_valid", "raw_rate_deviation", "raw_coloc_mean", "n_beacons_norm",
    "had_coloc_observation", "range_anomaly", "rssi_distance_mismatch",
    "rssi_colocation", "trajectory_shadowing", "traj_shadow_score",
    "traj_shadow_compared", "iat_entropy",
    # ── enrichment ──
    "rssi_mismatch_frac", "mismatch_m_mean",
    "identity_lifetime", "beacon_count_mean",
    "rsu_observer_count", "rsu_report_count", "rsu_verified_prob",
    "rsu_false_decision", "ctrl_trust", "ctrl_observer_count",
]

DEFAULT_HP = dict(alpha=0.4, beta=0.3, gamma=0.3, lam=1.0, mu=0.3,
                  sigma_ch=4.0, gamma_co=0.7)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Compact MLP  (φ_trust = 16-dim penultimate, the deployed trust score)
# ═══════════════════════════════════════════════════════════════════════════
class TrustMLP(nn.Module):
    def __init__(self, n_features, hidden1=32, hidden2=16, dropout=0.3):
        super().__init__()
        self.fc1 = nn.Linear(n_features, hidden1); self.act1 = nn.ReLU()
        self.drop = nn.Dropout(dropout)
        self.fc2 = nn.Linear(hidden1, hidden2); self.act2 = nn.ReLU()
        self.fc3 = nn.Linear(hidden2, 1)

    def forward(self, x):
        h1 = self.drop(self.act1(self.fc1(x)))
        phi = self.act2(self.fc2(h1))            # φ_trust(v_i), 16-dim
        return self.fc3(phi).squeeze(-1), phi


def build_pipeline(subsample_frac=0.4, window_w=10, hp=None, datasets=None, cache=None):
    """Load all runs → enriched windows. Returns the combined window table.
    If `cache` (a path) is given and exists, load it instead of re-reading the logs."""
    if cache and Path(cache).exists():
        print(f"  loading cached windows: {cache}")
        return pd.read_parquet(cache)
    hp = {**DEFAULT_HP, **(hp or {})}
    datasets = datasets or DATASETS
    parts = []
    for d in datasets:
        d = Path(d)
        if not d.exists():
            print(f"  SKIP (missing): {d}")
            continue
        w = build_run_windows(d, subsample_frac, window_w, hp)
        print(f"  {d.name}: {len(w):,} windows | pos_rate={w['label'].mean():.3f}")
        parts.append(w)
    windows = pd.concat(parts, ignore_index=True)
    windows["group_key"] = windows["run_id"] + "__vid" + windows["observed_real_id"].astype(str)
    if cache:
        Path(cache).parent.mkdir(parents=True, exist_ok=True)
        windows.to_parquet(cache, index=False)
        print(f"  cached windows -> {cache}")
    return windows


# ═══════════════════════════════════════════════════════════════════════════
# 5. Feature prep (train-only impute + standardize), split, metrics
# ═══════════════════════════════════════════════════════════════════════════
def compute_metrics(y_true, y_pred):
    from sklearn.metrics import (accuracy_score, f1_score, matthews_corrcoef,
                                 precision_score, recall_score)
    return {"mcc": matthews_corrcoef(y_true, y_pred),
            "f1": f1_score(y_true, y_pred, zero_division=0),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "accuracy": accuracy_score(y_true, y_pred)}


def group_stratified_split(df, group_col="group_key", strata_cols=("attack_percentage", "attack_type"),
                           val=0.15, test=0.15, seed=RNG_SEED):
    """Attach the SHARED split from identity_manifest (grouped by real vehicle;
    identical across RSSI / GRU / trust). Signature kept so the notebook driver is
    unchanged; the args are now ignored — the split is no longer computed here."""
    man = shared_manifest()
    df = df.copy()
    # Trust windows carry virtual per-attack-type run_ids ("pct100_s1_type3"),
    # but the shared manifest is keyed on the base run_id ("pct100_s1"). Strip the
    # _type<N> suffix before the lookup, else every key misses and split_of() falls
    # back to "train" for all rows (val/test end up empty).
    base_run = pd.Series(df["run_id"].to_numpy(), dtype="object").str.replace(
        r"_type\d+$", "", regex=True).to_numpy()
    df["split"] = IDM.split_of(base_run,
                               df["observed_claimed_id"].to_numpy(), man)
    return df


def prep_features(df, feature_cols=FEATURE_COLS):
    """Train-only median-impute + standardize. Returns (df, stats) with stats
    exportable so C++/inference standardizes identically."""
    df = df.copy()
    tr = df[df["split"] == "train"]
    med = tr[feature_cols].median(numeric_only=True)
    df[feature_cols] = df[feature_cols].fillna(med)
    mean = df.loc[df["split"] == "train", feature_cols].mean()
    std = df.loc[df["split"] == "train", feature_cols].std().replace(0, 1.0)
    df[feature_cols] = (df[feature_cols] - mean) / std
    stats = {"impute_median": med.to_dict(), "mean": mean.to_dict(), "std": std.to_dict()}
    return df, stats


# ═══════════════════════════════════════════════════════════════════════════
# 6. Hierarchical FL (FedProx + DP + RSU size-weighted avg + SDN trimmed-mean)
#    — reused from v1, unchanged (Eqs 3.26-3.28)
# ═══════════════════════════════════════════════════════════════════════════
def _clone(sd): return {k: v.clone() for k, v in sd.items()}


def build_client_cache(df, feature_cols):
    cache = {}
    for key, cdf in df.groupby(["run_id", "observer_vehicle_id"], sort=False):
        if len(cdf) < 2:
            continue
        X = torch.tensor(cdf[feature_cols].to_numpy(dtype=np.float32))
        y = torch.tensor(cdf["label"].to_numpy(dtype=np.float32))
        cache[key] = (X, y, (cdf["run_id"].iloc[0], int(cdf["rsu_id"].iloc[0])),
                      bool(cdf["label"].to_numpy().sum() > 0))
    return cache


def _local_train(gstate, X, y, epochs, lr, mu, bs, nf, pos_weight=None):
    m = TrustMLP(nf); m.load_state_dict(gstate); g = _clone(gstate)
    opt = torch.optim.Adam(m.parameters(), lr=lr)
    pw = torch.tensor([pos_weight], dtype=torch.float32) if pos_weight else None
    crit = nn.BCEWithLogitsLoss(pos_weight=pw)
    n = len(y); idx = np.arange(n)
    for _ in range(epochs):
        rng.shuffle(idx)
        for s in range(0, n, bs):
            b = idx[s:s + bs]
            opt.zero_grad()
            logit, _ = m(X[b]); loss = crit(logit, y[b])
            loss = loss + (mu / 2.0) * sum(((p - g[nm]) ** 2).sum() for nm, p in m.named_parameters())
            loss.backward(); opt.step()
    return m.state_dict(), n


def _fedavg(sds, ws):
    tot = float(sum(ws)); out = {}
    for k in sds[0]:
        out[k] = sum(sd[k].float() * (w / tot) for sd, w in zip(sds, ws))
    return out


def _trimmed_mean(sds, ref, trim_k):
    n = len(sds)
    if n <= 2 * trim_k:
        keep = list(range(n))
    else:
        norms = [sum((sd[k] - ref[k]).float().pow(2).sum().item() for k in sd) for sd in sds]
        keep = list(np.argsort(norms)[trim_k:n - trim_k])
    return {k: torch.stack([sds[i][k].float() for i in keep]).mean(0) for k in sds[0]}


def _select_clients(keys, has_pos, n_sel, min_pos_frac=0.5):
    pos = np.nonzero(has_pos)[0]
    n_pos = min(len(pos), max(1, int(np.ceil(n_sel * min_pos_frac))), n_sel)
    sel_pos = rng.choice(pos, size=n_pos, replace=False) if n_pos > 0 else np.array([], int)
    pool = np.setdiff1d(np.arange(len(keys)), sel_pos)
    rem = min(n_sel - len(sel_pos), len(pool))
    sel_rest = rng.choice(pool, size=rem, replace=False) if rem > 0 else np.array([], int)
    return np.concatenate([sel_pos, sel_rest]).astype(int)


def _fl_round(gstate, cache, keys, hp, nf, sel_frac=0.3, min_clients=8, pos_weight=None):
    n_sel = min(len(keys), max(min_clients, int(math.ceil(len(keys) * sel_frac))))
    has_pos = np.array([cache[k][3] for k in keys])
    rsu_up: Dict[Tuple, List] = {}
    tot = 0
    for si in _select_clients(keys, has_pos, n_sel):
        X, y, rkey, _ = cache[keys[si]]
        ls, n = _local_train(gstate, X, y, hp["local_epochs"], hp["local_lr"],
                             hp["fedprox_mu"], hp["batch_size"], nf, pos_weight)
        noised = {k: gstate[k] + (v - gstate[k]) + torch.randn(v.shape) * hp["dp_sigma"]
                  for k, v in ls.items()}
        rsu_up.setdefault(rkey, []).append((noised, n)); tot += n
    if not rsu_up:
        return gstate, 0
    rsu_states = [_fedavg([m[0] for m in mem], [m[1] for m in mem]) for mem in rsu_up.values()]
    return _trimmed_mean(rsu_states, gstate, hp["trim_k"]), tot


def evaluate_state(state, df, feature_cols, nf, threshold=0.5):
    m = TrustMLP(nf, dropout=0.0); m.load_state_dict(state); m.eval()
    X = torch.tensor(df[feature_cols].to_numpy(dtype=np.float32))
    with torch.no_grad():
        logit, phi = m(X); probs = torch.sigmoid(logit).numpy()
    return compute_metrics(df["label"].to_numpy(), (probs >= threshold).astype(int)), probs, phi.numpy()


def centralized_pretrain(tr, feature_cols, nf, epochs=3, lr=0.01, dropout=0.1, bs=64, pos_weight=None):
    torch.manual_seed(RNG_SEED)
    m = TrustMLP(nf, dropout=dropout); opt = torch.optim.Adam(m.parameters(), lr=lr)
    pw = torch.tensor([pos_weight], dtype=torch.float32) if pos_weight else None
    crit = nn.BCEWithLogitsLoss(pos_weight=pw)
    X = torch.tensor(tr[feature_cols].to_numpy(dtype=np.float32))
    y = torch.tensor(tr["label"].to_numpy(dtype=np.float32))
    idx = np.arange(len(y))
    for _ in range(epochs):
        rng.shuffle(idx)
        for s in range(0, len(idx), bs):
            b = idx[s:s + bs]; opt.zero_grad()
            logit, _ = m(X[b]); crit(logit, y[b]).backward(); opt.step()
    return m.state_dict()


def train_fl(tr, va, feature_cols, hp, nf, max_rounds=25, patience=6, min_delta=1e-3,
             sel_frac=0.3, min_clients=8, pos_weight=None, warm_start=None, verbose=True):
    torch.manual_seed(RNG_SEED)
    gstate = _clone(warm_start) if warm_start is not None else _clone(TrustMLP(nf, dropout=hp.get("dropout", 0.3)).state_dict())
    cache = build_client_cache(tr, feature_cols); keys = list(cache.keys())
    hist = []; best_mcc, best_state, bad = -1.0, gstate, 0
    for r in range(1, max_rounds + 1):
        gstate, n = _fl_round(gstate, cache, keys, hp, nf, sel_frac, min_clients, pos_weight)
        vm, _, _ = evaluate_state(gstate, va, feature_cols, nf)
        hist.append({"round": r, "val_mcc": vm["mcc"], "val_f1": vm["f1"]})
        if vm["mcc"] > best_mcc + min_delta:
            best_mcc, best_state, bad = vm["mcc"], _clone(gstate), 0
        else:
            bad += 1
        if verbose and (r == 1 or r % 5 == 0 or bad >= patience):
            print(f"  round {r:3d}  val_mcc={vm['mcc']:.4f}  best={best_mcc:.4f}")
        if bad >= patience:
            break
    return best_state, pd.DataFrame(hist), best_mcc


# ═══════════════════════════════════════════════════════════════════════════
# 7. Rich export — per-window scores (contract key) + φ_trust + weights JSON
# ═══════════════════════════════════════════════════════════════════════════
def export_scores(df, state, feature_cols, out_csv):
    """Per-window trust scores keyed (claimed_node_id, window_start_seconds, split):
    attack_type∈{0..6}, is_sybil, T components, φ_trust(16), enriched signals."""
    _, probs, phi = evaluate_state(state, df, feature_cols, len(feature_cols))
    out = pd.DataFrame({
        "claimed_node_id": df["observed_claimed_id"].to_numpy(),
        "window_start_seconds": df["window_start"].to_numpy(),
        "window_end_seconds": df["window_end"].to_numpy(),
        "split": df["split"].to_numpy(),
        "run_id": df["run_id"].to_numpy(),
        "attack_percentage": df["attack_percentage"].to_numpy(),   # static pool % (metadata)
        "active_attack_pct": df["active_attack_pct"].to_numpy() if "active_attack_pct" in df else np.nan,  # intensity ladder (EVAL-ONLY metadata)
        "attack_type": df["attack_type"].to_numpy(),          # 0..6
        "is_sybil": df["label"].to_numpy(),
        "phi_trust_score": probs,                              # sigmoid head (deployed scalar)
        "T_RSSI": df["T_RSSI"].to_numpy(), "T_behav": df["T_behav"].to_numpy(),
        "T_hist": df["T_hist"].to_numpy(), "T_composite": df["T_composite"].to_numpy(),
    })
    for j in range(phi.shape[1]):                              # φ_trust 16-dim embedding
        out[f"phi_trust_{j}"] = phi[:, j]
    # a few interpretable enriched signals for the LLM context
    for c in ["rssi_mismatch_frac", "mismatch_m_mean", "identity_lifetime",
              "rsu_report_count", "rsu_verified_prob", "ctrl_trust",
              "iat_entropy", "raw_coloc_mean", "token_valid"]:
        if c in df:
            out[c] = df[c].to_numpy()
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv, index=False)
    return out


def export_fusion_parquet(df, state, feature_cols, out_parquet=None):
    """Grid-snapped fusion contract twin of the RSSI/GRU parquets: one row per
    (run_id, claimed_node_id, window_start_seconds[snapped to 2 s], split) with
    phi_trust_0..15 + phi_trust_score + T_composite, so the three vehicle-tier
    tables inner-join for Eq 3.18 / Eq 3.31. Writes notebooks/outputs/ by default."""
    out_parquet = out_parquet or (ARTIFACTS_DIR / "trust_vehicle_tier.parquet")
    _, probs, phi = evaluate_state(state, df, feature_cols, len(feature_cols))
    w = pd.DataFrame({
        "run_id": df["run_id"].to_numpy(),
        "attack_percentage": df["attack_percentage"].to_numpy(),
        "claimed_node_id": df["observed_claimed_id"].astype(int).to_numpy(),
        "window_start_seconds": IDM.snap_grid(df["window_start"].to_numpy()),
        "split": df["split"].to_numpy(),
        "is_sybil": df["label"].to_numpy(),
        "attack_type": df["attack_type"].to_numpy(),
        "active_attack_pct": (df["active_attack_pct"].to_numpy()
                              if "active_attack_pct" in df else np.nan),
        "phi_trust_score": probs,
        "T_composite": df["T_composite"].to_numpy(),
    })
    phi_cols = [f"phi_trust_{j}" for j in range(phi.shape[1])]
    for j in range(phi.shape[1]):
        w[phi_cols[j]] = phi[:, j]
    # Eq 3.31 trust-token sub-fields (interpretable) + FP-reduction evidence, so
    # cᵢ reasons over signal / behaviour / history trust separately rather than
    # an opaque composite. Only those present in df are emitted (robust).
    SUBFIELD_COLS = ["T_RSSI", "T_behav", "T_hist",
                     "rssi_mismatch_frac", "identity_lifetime",
                     "rsu_report_count", "rsu_verified_prob", "ctrl_trust"]
    subfields = [c for c in SUBFIELD_COLS if c in df.columns]
    for c in subfields:
        w[c] = df[c].to_numpy()
    key = ["run_id", "attack_percentage", "claimed_node_id", "window_start_seconds", "split"]
    agg = {**{c: "mean" for c in phi_cols}, "phi_trust_score": "mean",
           "T_composite": "mean", "is_sybil": "max", "active_attack_pct": "first",
           **{c: "mean" for c in subfields}}
    pooled = w.groupby(key, as_index=False).agg(agg)
    at = (w.groupby(key)["attack_type"]
            .agg(lambda s: int(pd.Series(s[s > 0]).mode().iloc[0]) if (s > 0).any() else 0)
            .reset_index())
    out = pooled.merge(at, on=key)
    out = out[key + ["is_sybil", "attack_type", "active_attack_pct",
                     "phi_trust_score", "T_composite"] + subfields + phi_cols]
    Path(out_parquet).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(out_parquet, index=False)
    return out


def export_weights_json(state, feature_cols, stats, hp, out_json):
    payload = {
        "feature_columns": feature_cols,
        "impute_median": stats["impute_median"],
        "feature_mean": stats["mean"], "feature_std": stats["std"],
        "trust_equation_hyperparameters": {k: hp[k] for k in
            ("alpha", "beta", "gamma", "lam", "mu", "sigma_ch", "gamma_co") if k in hp},
        "model_hyperparameters": {"hidden1": 32, "hidden2": 16, "dropout": 0.3,
                                  "phi_trust_dim": 16},
        "layers": {k: v.cpu().numpy().tolist() for k, v in state.items()},
    }
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(json.dumps(payload, indent=2))
    return out_json


def load_model_json(path):
    """Rebuild a trained TrustMLP state_dict + standardization stats from the
    exported weights JSON (for scoring a NEW dataset with a trained model)."""
    d = json.loads(Path(path).read_text())
    sd = {k: torch.tensor(v, dtype=torch.float32) for k, v in d["layers"].items()}
    stats = {"impute_median": pd.Series(d["impute_median"]),
             "mean": pd.Series(d["feature_mean"]), "std": pd.Series(d["feature_std"])}
    return sd, stats, d["feature_columns"]


def apply_stats(df, feature_cols, stats):
    df = df.copy()
    df[feature_cols] = df[feature_cols].fillna(stats["impute_median"])
    df[feature_cols] = (df[feature_cols] - stats["mean"]) / stats["std"].replace(0, 1.0)
    return df


def score_dataset(model_json, target_datasets, out_csv, frac=0.3, cache=None):
    """Score a TARGET run (e.g. seq6_full_s1, the fusion eval set) with a model
    trained elsewhere (the pct sweep). Produces the trust CSV that
    ml/fullmode/build_evidence.py joins onto the spine of the SAME run."""
    sd, stats, fcols = load_model_json(model_json)
    W = build_pipeline(subsample_frac=frac, datasets=target_datasets, cache=cache)
    W["split"] = "score"
    W = apply_stats(W, fcols, stats)
    out = export_scores(W, sd, fcols, out_csv)
    print(f"scored {len(out):,} windows of {[Path(d).name for d in target_datasets]} -> {out_csv}")
    return out


if __name__ == "__main__":
    import argparse, time
    ap = argparse.ArgumentParser()
    ap.add_argument("--frac", type=float, default=0.05)
    ap.add_argument("--datasets", nargs="*", default=None)
    ap.add_argument("--cache", default=str(_HERE / "cache" / "windows.parquet"))
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--train", action="store_true")
    # scoring mode: apply a trained model to a target run for the fusion join
    ap.add_argument("--score-dataset", nargs="*", default=None,
                    help="target run dir(s) to score with --model (e.g. datasets/seq6_full_s1)")
    ap.add_argument("--model", default=str(_HERE / "outputs" / "vehicle_trust_mlp_v2.json"))
    ap.add_argument("--score-out", default=str(_HERE / "outputs" / "vehicle_trust_scores_seq6_full_s1.csv"))
    args = ap.parse_args()

    if args.score_dataset:
        score_dataset(args.model, [Path(x) for x in args.score_dataset], args.score_out,
                      frac=args.frac, cache=None)
        raise SystemExit(0)
    ds = [Path(x) for x in args.datasets] if args.datasets else None
    t0 = time.time()
    W = build_pipeline(subsample_frac=args.frac, datasets=ds, cache=args.cache)
    print(f"\nTOTAL windows: {len(W):,}  in {time.time()-t0:.0f}s")
    print("label dist:", W["label"].value_counts().to_dict())
    print("attack_type dist:", W["attack_type"].value_counts().to_dict())

    W = group_stratified_split(W)
    W, stats = prep_features(W)
    print("split:", W["split"].value_counts().to_dict())
    nf = len(FEATURE_COLS)
    tr, va, te = [W[W.split == s] for s in ("train", "val", "test")]

    if args.train:
        pos_rate = tr["label"].mean()
        pw = float(np.clip((1 - pos_rate) / max(pos_rate, 1e-6), 1.0, 20.0))
        hp = dict(dropout=0.1, fedprox_mu=0.001, dp_sigma=0.02, local_lr=0.05,
                  batch_size=32, local_epochs=2, trim_k=1)
        warm = centralized_pretrain(tr, FEATURE_COLS, nf, epochs=3, pos_weight=pw)
        wm, _, _ = evaluate_state(warm, va, FEATURE_COLS, nf)
        print(f"warm-start val MCC={wm['mcc']:.4f}")
        state, hist, best = train_fl(tr, va, FEATURE_COLS, hp, nf, max_rounds=args.rounds,
                                     pos_weight=pw, warm_start=warm)
        tm, _, _ = evaluate_state(state, te, FEATURE_COLS, nf)
        print(f"TEST: MCC={tm['mcc']:.4f} F1={tm['f1']:.4f} recall={tm['recall']:.4f} prec={tm['precision']:.4f}")
        out = export_scores(W, state, FEATURE_COLS, _HERE / "outputs" / "vehicle_trust_scores_v2.csv")
        export_weights_json(state, FEATURE_COLS, stats, {**DEFAULT_HP, **hp},
                            _HERE / "outputs" / "vehicle_trust_mlp_v2.json")
        print(f"exported {len(out):,} scored windows + weights -> {_HERE/'outputs'}")
