"""
vehicle_trust/predict.py — label-free, manifest-free real-time inference for the
vehicle trust analyzer (Phase 1 of the real-time full-mode integration).

Reuses the trained TrustMLP (outputs/vehicle_trust_mlp_v2.json) and the PURE
feature functions in trust_v2_lib, but REPLACES the training-only loader
(`build_run_windows`: identity-manifest subsample + phase-derived labels + virtual
per-attack-type run_ids) with a causal, ALL-identities path suitable for scoring a
live/finished run's logs up to a cutoff time t.

What is intentionally dropped versus the training pipeline (none are model inputs):
  * the identity-manifest subsample  -> score every observed identity;
  * phase-table labels / is_sybil / attack_type / virtual _typeN run_ids -> unknown
    at inference, set to dummies (they are metadata, never in FEATURE_COLS);
  * the shared train/val/test split and active_attack_pct (eval-only metadata).

Kept verbatim (label-free, reused from trust_v2_lib): the RSSI as-of merge, the
cross-tier consensus merge, `_decompose_suspicion`, `_aggregate_windows`,
`add_coloc_features`, `add_trust_scores`, `apply_stats`, and the TrustMLP forward.

API:
  p = TrustPredictor.load()                       # loads weights + trust-eq hp
  df = p.score_logs(run_dir, t=None, run_id="live")   # -> spine-schema DataFrame

Output columns (the trust slice of the fusion spine contract):
  run_id, claimed_node_id, window_start_seconds (2 s grid),
  phi_trust_0..15, phi_trust_score, T_composite, T_RSSI, T_behav, T_hist,
  + evidence (rssi_mismatch_frac, identity_lifetime, rsu_report_count,
    rsu_verified_prob, ctrl_trust) where the source logs are present.
"""

import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
# trust_v2_lib resolves identity_manifest relative to its own dir (ml/analyzers/
# fusion, which does not exist); add the REAL fusion dir (ml/fusion) first so the
# import succeeds regardless of where predict.py is invoked from.
sys.path.insert(0, str(_HERE.parents[1] / "fusion"))
import trust_v2_lib as T          # noqa: E402  (pure feature fns + TrustMLP + constants)

DEFAULT_MODEL = _HERE / "outputs" / "vehicle_trust_mlp_v2.json"

# evidence sub-fields carried into the LLM context (only if present in the windows)
EVIDENCE_COLS = ["rssi_mismatch_frac", "identity_lifetime",
                 "rsu_report_count", "rsu_verified_prob", "ctrl_trust"]


def build_windows_live(run_dir, hp, t=None, run_id="live", window_w=10, nrows=None, rows=None,
                       rssi_rows=None):
    """Causal, label-free twin of trust_v2_lib.build_run_windows.

    Reads the neighbor(+rssi+consensus) logs of `run_dir` up to time t (inclusive),
    keeps ALL identities, and returns the enriched per-(observer, claimed, window)
    trust table. `rows`: pre-read neighbor DataFrame already filtered to <= t (daemon
    LogCache fast path). `rssi_rows`: likewise for the RSSI log — see the merge below.
    `nrows` bounds the raw CSV read (earliest rows) for quick tests.
    """
    run_dir = Path(run_dir)
    if rows is not None:
        neighbor = rows.copy()
    else:
        neighbor = pd.read_csv(run_dir / T.NEIGHBOR_LOG,
                               usecols=lambda c: c in T.NEIGHBOR_COLS, nrows=nrows)
        if t is not None:
            neighbor = neighbor[neighbor["time"] <= float(t)].copy()
    if neighbor.empty:
        return pd.DataFrame()

    # dtypes (mirror build_run_windows)
    for c in ("bsm_x", "bsm_y", "bsm_speed", "bsm_heading", "estimated_distance",
              "first_seen_time", "last_seen_time"):
        if c in neighbor:
            neighbor[c] = neighbor[c].astype("float32")
    for c in ("observer_vehicle_id", "observed_real_id", "observed_claimed_id",
              "received_beacon_count"):
        neighbor[c] = neighbor[c].astype("int64")

    neighbor = T._decompose_suspicion(neighbor)
    # LABEL-FREE: no phase table at inference. is_sybil/attack_type are metadata
    # consumed only by _aggregate_windows' bookkeeping columns, never features.
    neighbor["is_sybil"] = 0
    neighbor["attack_type"] = 0
    neighbor["token_valid"] = (
        (neighbor["suspicion_flags"].fillna(0).astype("int64") & T.SUSP_INVALID_V2V_SIGNATURE) == 0
    ).astype(int)

    # ── RSSI verification as-of merge (per observer+claimed) — verbatim logic ──
    # `rssi_rows`: pre-read RSSI slice from the daemon's LogCache (fast path). The merge
    # below is as-of on time with a 0.5 s tolerance, so any slice that covers the neighbor
    # rows' span padded past that tolerance yields IDENTICAL matches to the full-history
    # read it replaces — without re-parsing a several-hundred-MB CSV on every window.
    rssi_path = run_dir / T.RSSI_LOG
    if rssi_rows is not None:
        rssi = rssi_rows
    elif rssi_path.exists() and rssi_path.stat().st_size > 100:
        rssi = pd.read_csv(rssi_path, usecols=lambda c: c in T.RSSI_COLS, nrows=nrows)
    else:
        rssi = None
    if rssi is not None and len(rssi):
        if t is not None:
            rssi = rssi[rssi["time"] <= float(t)]
        rssi = rssi.dropna(subset=["time", "observer_vehicle_id", "observed_claimed_id"]).copy()
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

    # ── cross-tier consensus as-of merge (tiny logs) — verbatim logic ──
    for _tier, cdf in T.load_consensus(run_dir):
        cdf = cdf.dropna(subset=["time", "observed_claimed_id"]).sort_values("time").copy()
        cdf["observed_claimed_id"] = cdf["observed_claimed_id"].astype("int64")
        cdf["time"] = cdf["time"].astype("float64")
        neighbor["time"] = neighbor["time"].astype("float64")
        neighbor["observed_claimed_id"] = neighbor["observed_claimed_id"].astype("int64")
        neighbor = pd.merge_asof(
            neighbor.sort_values("time"), cdf, on="time",
            by="observed_claimed_id", direction="backward", tolerance=30.0)

    vmap = T.load_vehicle_to_rsu(run_dir)
    neighbor["rsu_id"] = neighbor["observer_vehicle_id"].map(vmap).fillna(-1).astype(int)
    neighbor["run_id"] = run_id                 # REAL run id, not virtual _typeN
    neighbor["attack_percentage"] = 0           # dummy metadata

    w = T._aggregate_windows(neighbor, window_w)
    del neighbor
    if w.empty:
        return w
    w = T.add_coloc_features(w, hp["sigma_ch"], hp["gamma_co"])
    w = T.add_trust_scores(w, hp["alpha"], hp["beta"], hp["gamma"], hp["lam"], hp["mu"])
    return w


class TrustPredictor:
    """Trained TrustMLP + trust-equation hyperparameters, for live scoring."""

    def __init__(self, sd, stats, fcols, hp):
        self.stats = stats
        self.fcols = fcols
        self.hp = hp
        self.model = T.TrustMLP(len(fcols))
        self.model.load_state_dict(sd)
        self.model.eval()

    @classmethod
    def load(cls, model_json=DEFAULT_MODEL):
        sd, stats, fcols = T.load_model_json(model_json)
        d = json.loads(Path(model_json).read_text())
        hp = {**T.DEFAULT_HP, **d.get("trust_equation_hyperparameters", {})}
        return cls(sd, stats, fcols, hp)

    def score_windows(self, w):
        """Enriched windows -> pooled spine-schema rows with phi_trust + scores."""
        ws = T.apply_stats(w, self.fcols, self.stats)
        X = torch.tensor(ws[self.fcols].to_numpy(dtype="float32"))
        with torch.no_grad():
            logits, phi = self.model(X)
            prob = torch.sigmoid(logits).numpy()
            phi = phi.numpy()

        out = pd.DataFrame({
            "run_id": w["run_id"].to_numpy(),
            "claimed_node_id": w["observed_claimed_id"].astype(int).to_numpy(),
            "window_start_seconds": T.IDM.snap_grid(w["window_start"].to_numpy()),
            "phi_trust_score": prob,
            "T_composite": w["T_composite"].to_numpy(),
            "T_RSSI": w["T_RSSI"].to_numpy(),
            "T_behav": w["T_behav"].to_numpy(),
            "T_hist": w["T_hist"].to_numpy(),
        })
        phi_cols = [f"phi_trust_{j}" for j in range(phi.shape[1])]
        for j, col in enumerate(phi_cols):
            out[col] = phi[:, j]
        for c in EVIDENCE_COLS:
            if c in w:
                out[c] = w[c].to_numpy()

        # pool duplicate (run_id, claimed, snapped-window) rows -> one per grid cell,
        # matching export_fusion_parquet (mean of phi/scores), minus split/labels.
        key = ["run_id", "claimed_node_id", "window_start_seconds"]
        agg = {**{c: "mean" for c in phi_cols}, "phi_trust_score": "mean",
               "T_composite": "mean", "T_RSSI": "mean", "T_behav": "mean", "T_hist": "mean"}
        for c in EVIDENCE_COLS:
            if c in out:
                agg[c] = "mean"
        return out.groupby(key, as_index=False).agg(agg)

    def score_logs(self, run_dir, t=None, run_id="live", window_w=10, nrows=None, rows=None,
                   rssi_rows=None):
        """Score a run's logs up to time t; returns pooled spine-schema DataFrame."""
        w = build_windows_live(run_dir, self.hp, t=t, run_id=run_id,
                               window_w=window_w, nrows=nrows, rows=rows,
                               rssi_rows=rssi_rows)
        if w is None or w.empty:
            return pd.DataFrame()
        return self.score_windows(w)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Score a run's logs with the trained trust MLP.")
    ap.add_argument("run_dir")
    ap.add_argument("--t", type=float, default=None, help="causal cutoff (sim seconds)")
    ap.add_argument("--run-id", default="live")
    ap.add_argument("--nrows", type=int, default=None, help="bound raw CSV read (test)")
    ap.add_argument("--model", default=str(DEFAULT_MODEL))
    ap.add_argument("--out", default=None, help="optional parquet output path")
    args = ap.parse_args()

    p = TrustPredictor.load(args.model)
    df = p.score_logs(args.run_dir, t=args.t, run_id=args.run_id, nrows=args.nrows)
    print(f"scored {len(df):,} (run_id, claimed_id, window) rows")
    if len(df):
        print("cols:", list(df.columns))
        print("phi_trust_score range: [%.3f, %.3f]" % (df["phi_trust_score"].min(),
                                                        df["phi_trust_score"].max()))
        print("T_composite   range: [%.3f, %.3f]" % (df["T_composite"].min(),
                                                      df["T_composite"].max()))
        print(df.head(3).to_string())
    if args.out and len(df):
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        df.to_parquet(args.out, index=False)
        print("wrote", args.out)
