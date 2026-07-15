"""
temporal_xgb_rsu/predict.py — label-free RSU-tier temporal XGBoost inference (v3),
producing p̄_temp for the Eq 3.20 ensemble (Phase 1, RSU tier).

Reproduces temporal_xgb_seq_v3.ipynb's feature extraction VERBATIM (the 31 RSU-observable
behavioural + cross-identity context features over 5 s / 2 s fixed-time windows), minus
the training-only coupling (identity-manifest subsample, phase-table labels, split).
Loads the saved model — never refits:
    outputs/temporal_xgb_rsu.json   (XGBClassifier, 7-class)

Input = communication_log RSU receptions (receiver_role == rsu_edge, flow in
{v2v_beacon, v2rsu_report}), deduped to observer_count. p̄_temp = 1 − P(legit).
Windows are already on the 2 s grid (step == grid); snap + mean-pool defensively.

API:
  p = TemporalXGBPredictor.load()
  df = p.score_logs(run_dir, t=None, run_id="live")  # -> run_id, claimed_node_id,
       window_start_seconds, p_bar_temp, p_temp_xgb_0..6
"""

import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1] / "fusion"))
import identity_manifest as IDM          # noqa: E402  (snap_grid)

MODEL_JSON = _HERE / "outputs" / "temporal_xgb_rsu.json"
N_CLASSES, LEGIT = 7, 0
WINDOW_SIZE_S, WINDOW_STEP_S, MIN_BEACONS_WINDOW = 5.0, 2.0, 2

USE_COLS = ["receive_time", "flow", "receiver_role", "receiver_id", "real_node_id",
            "claimed_node_id", "message_type", "sequence_number", "packet_size", "delay",
            "bsm_temporary_id", "bsm_msg_count", "bsm_x", "bsm_y", "bsm_speed", "bsm_heading"]
RSU_RX_FLOWS = ["v2v_beacon", "v2rsu_report"]
BEACON_KEY = ["real_node_id", "claimed_node_id", "bsm_temporary_id", "receive_time"]

FEATURES = [
    "n_beacons", "n_distinct_temp_ids", "temp_id_churn_rate", "temp_id_change_count",
    "claimed_id_age_s", "claimed_id_beacons_seen_so_far",
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_entropy",
    "gap_since_prev_window", "beacon_rate_hz", "pos_x_var", "pos_y_var",
    "speed_mean", "speed_std", "heading_std", "speed_consistency_err_mean",
    "packet_size_mean", "delay_mean", "delay_std", "observer_count_mean", "observer_count_std",
    "msg_count_span", "msg_count_reset_flag",
    "active_claimed_ids_window", "active_temp_ids_window", "shared_temp_id_count_window",
    "max_claimed_per_temp_id_window", "new_claimed_ids_window",
]


# ── notebook functions, VERBATIM (feature parity by construction) ─────────────
def shannon_entropy(values, n_bins=10):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) < 2:
        return np.nan
    rng = values.max() - values.min()
    if rng <= 1e-12:
        return 0.0
    counts, _ = np.histogram(values, bins=n_bins, range=(values.min(), values.max()))
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def build_global_context(b_sorted, window_size, window_step):
    t = b_sorted["receive_time"].values
    cid = b_sorted["claimed_node_id"].values
    tid = b_sorted["bsm_temporary_id"].values
    first_seen = b_sorted.groupby("claimed_node_id")["receive_time"].min().values
    t0, t1 = float(t.min()), float(t.max())
    starts = np.arange(np.floor(t0), t1 + window_step, window_step)
    ctx = {}
    for s in starts:
        e = s + window_size
        lo = np.searchsorted(t, s)
        hi = np.searchsorted(t, e)
        if hi <= lo:
            ctx[round(float(s), 6)] = (0, 0, 0, 0, 0)
            continue
        sub = pd.DataFrame({"cid": cid[lo:hi], "tid": tid[lo:hi]})
        claimed_per_temp = sub.groupby("tid")["cid"].nunique()
        new_ids = int(((first_seen >= s) & (first_seen < e)).sum())
        ctx[round(float(s), 6)] = (
            int(sub["cid"].nunique()), int(sub["tid"].nunique()),
            int((claimed_per_temp > 1).sum()),
            int(claimed_per_temp.max()) if len(claimed_per_temp) else 0, new_ids)
    return ctx, starts


def build_feature_table(beacons_df, window_size=WINDOW_SIZE_S, window_step=WINDOW_STEP_S,
                        min_beacons=MIN_BEACONS_WINDOW):
    b = beacons_df.sort_values("receive_time").reset_index(drop=True)
    context, starts = build_global_context(b, window_size, window_step)
    first_seen_global = b.groupby("claimed_node_id")["receive_time"].min().to_dict()
    rows = []
    for cidv, g in b.groupby("claimed_node_id"):
        g = g.sort_values("receive_time").reset_index(drop=True)
        gt0, gt1 = g["receive_time"].min(), g["receive_time"].max()
        fs = first_seen_global[cidv]
        rel = starts[(starts <= gt1) & (starts + window_size > gt0)]
        prev_end = None
        for s in rel:
            e = s + window_size
            w = g[(g["receive_time"] >= s) & (g["receive_time"] < e)]
            if len(w) < min_beacons:
                continue
            iats = np.diff(w["receive_time"].values)
            tids = w["bsm_temporary_id"].astype(str).values
            tch = max(int((tids[1:] != tids[:-1]).sum()), 0) if len(tids) > 1 else 0
            gap = (s - prev_end) if prev_end is not None else 0.0
            beacons_so_far = int((g["receive_time"] < e).sum())
            dx = np.diff(w["bsm_x"].values)
            dy = np.diff(w["bsm_y"].values)
            sp = w["bsm_speed"].values
            exp_dx = sp[:-1] * np.cos(np.radians(w["bsm_heading"].values[:-1])) * iats if len(iats) else np.array([0.])
            exp_dy = sp[:-1] * np.sin(np.radians(w["bsm_heading"].values[:-1])) * iats if len(iats) else np.array([0.])
            speed_err = np.sqrt((dx - exp_dx) ** 2 + (dy - exp_dy) ** 2).mean() if len(dx) else 0.0
            ctx_key = min(context.keys(), key=lambda k: abs(k - round(float(s), 6)))
            ac, at, st, mc, ni = context[ctx_key]
            msg_counts = w["bsm_msg_count"].values
            rows.append({
                "claimed_node_id": cidv, "window_start": float(s), "window_end": float(e),
                "n_beacons": len(w),
                "n_distinct_temp_ids": int(w["bsm_temporary_id"].nunique()),
                "temp_id_churn_rate": tch / max(len(tids) - 1, 1),
                "temp_id_change_count": tch,
                "claimed_id_age_s": float(s) - fs,
                "claimed_id_beacons_seen_so_far": beacons_so_far,
                "iat_mean": float(iats.mean()) if len(iats) else 0.0,
                "iat_std": float(iats.std()) if len(iats) else 0.0,
                "iat_min": float(iats.min()) if len(iats) else 0.0,
                "iat_max": float(iats.max()) if len(iats) else 0.0,
                "iat_entropy": shannon_entropy(iats),
                "gap_since_prev_window": gap,
                "beacon_rate_hz": len(w) / window_size,
                "pos_x_var": float(w["bsm_x"].var()),
                "pos_y_var": float(w["bsm_y"].var()),
                "speed_mean": float(sp.mean()),
                "speed_std": float(sp.std()),
                "heading_std": float(w["bsm_heading"].std()),
                "speed_consistency_err_mean": speed_err,
                "packet_size_mean": float(w["packet_size"].mean()),
                "delay_mean": float(w["delay"].mean()),
                "delay_std": float(w["delay"].std()),
                "observer_count_mean": float(w["observer_count"].mean()),
                "observer_count_std": float(w["observer_count"].std()),
                "msg_count_span": int(msg_counts.max() - msg_counts.min()) if len(msg_counts) > 1 else 0,
                "msg_count_reset_flag": int((np.diff(msg_counts) < 0).any()) if len(msg_counts) > 1 else 0,
                "active_claimed_ids_window": ac,
                "active_temp_ids_window": at,
                "shared_temp_id_count_window": st,
                "max_claimed_per_temp_id_window": mc,
                "new_claimed_ids_window": ni,
            })
            prev_end = e
    return pd.DataFrame(rows)


def dedup_beacons(df):
    dup = (df.groupby(BEACON_KEY)["receiver_id"].nunique()
             .rename("observer_count").reset_index())
    agg_cols = [c for c in df.columns if c not in ["receiver_id", "receiver_role"]]
    b = df.sort_values("receive_time").groupby(BEACON_KEY, as_index=False)[agg_cols].first()
    b = b.merge(dup, on=BEACON_KEY, how="left")
    return b.sort_values(["claimed_node_id", "receive_time"]).reset_index(drop=True)


def full_proba(model, X):
    """predict_proba padded to (N, 7) regardless of classes seen in training."""
    p = model.predict_proba(X)
    full = np.zeros((len(X), N_CLASSES), dtype=np.float32)
    for j, c in enumerate(model.classes_):
        full[:, int(c)] = p[:, j]
    return full


def build_features_live(run_dir, t=None, run_id="live", nrows=None):
    df = pd.read_csv(Path(run_dir) / "communication_log.csv",
                     usecols=lambda c: c in set(USE_COLS), nrows=nrows)
    df = df[(df["receiver_role"] == "rsu_edge") & (df["flow"].isin(RSU_RX_FLOWS))].copy()
    if t is not None:
        df = df[df["receive_time"] <= float(t)]
    if df.empty:
        return pd.DataFrame()
    b = dedup_beacons(df)
    fdf = build_feature_table(b)
    if fdf.empty:
        return fdf
    fdf["run_id"] = run_id
    return fdf


class TemporalXGBPredictor:
    def __init__(self, model):
        self.model = model

    @classmethod
    def load(cls, model_json=MODEL_JSON):
        m = xgb.XGBClassifier()
        m.load_model(str(model_json))
        return cls(m)

    def score_logs(self, run_dir, t=None, run_id="live", nrows=None):
        fdf = build_features_live(run_dir, t=t, run_id=run_id, nrows=nrows)
        if fdf is None or fdf.empty:
            return pd.DataFrame()
        fp = full_proba(self.model, fdf[FEATURES])
        out = pd.DataFrame({
            "run_id": fdf["run_id"].to_numpy(),
            "claimed_node_id": fdf["claimed_node_id"].astype(int).to_numpy(),
            "window_start_seconds": IDM.snap_grid(fdf["window_start"].to_numpy()),
            "p_bar_temp": (1.0 - fp[:, LEGIT]).astype(np.float32),
        })
        for k in range(N_CLASSES):
            out[f"p_temp_xgb_{k}"] = fp[:, k].astype(np.float32)
        key = ["run_id", "claimed_node_id", "window_start_seconds"]
        val = ["p_bar_temp"] + [f"p_temp_xgb_{k}" for k in range(N_CLASSES)]
        return out.groupby(key, as_index=False)[val].mean()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--t", type=float, default=None)
    ap.add_argument("--run-id", default="live")
    ap.add_argument("--nrows", type=int, default=None)
    ap.add_argument("--model", default=str(MODEL_JSON))
    args = ap.parse_args()
    p = TemporalXGBPredictor.load(args.model)
    df = p.score_logs(args.run_dir, t=args.t, run_id=args.run_id, nrows=args.nrows)
    print(f"scored {len(df):,} (run_id, claimed_id, window) rows")
    if len(df):
        print("cols:", list(df.columns))
        print("p_bar_temp range: [%.3f, %.3f] mean=%.3f" % (
            df.p_bar_temp.min(), df.p_bar_temp.max(), df.p_bar_temp.mean()))
        print(df.head(3).to_string())
