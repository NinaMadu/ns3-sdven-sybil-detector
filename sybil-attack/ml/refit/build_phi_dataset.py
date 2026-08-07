"""
build_phi_dataset — extract current-distribution φ (+ labels) for the head refit.

Why this exists
---------------
The bi-GRU ENCODER still separates fakes from honest vehicles on today's runs (best single
φ_temp dim AUC 0.930; a fresh probe on φ reaches MCC 0.906). What broke is the two FROZEN
LINEAR MAPS fitted on July's φ cloud: the GRU's softmax head (live binary MCC 0.000, and
AUC(1-p_temp_0) = 0.178 — inverted) and the Eq 3.18 fusion head (AUC 0.9654 on the training
spine → 0.1025 live). The φ centroid moved 3.74 in L2 against a training centroid norm of
1.884, i.e. the cloud translated wholesale out of the region where the boundaries were fit.
Linear separability survives translation; a fixed decision boundary does not.

So: freeze the encoders, re-fit only the last layers on φ extracted from CURRENT runs.
This script produces that φ table. refit_heads.py consumes it.

Labels
------
Reproduces temporal_gru_seq_v4.ipynb's rule EXACTLY, so the refit head is trained on the same
target definition as the original:
    per beacon : attack_type = run's type if real_node_id != claimed_node_id else 0
    per window : if any beacon is sybil -> mode of the NON-ZERO types; else 0
    is_sybil   : attack_type > 0
Note this is the `real != claimed` oracle, NOT `claimed_id >= N_Vehicles`.

Pooling matches the deployed predictors: mean over (run_id, claimed_node_id, 2 s grid cell).
Labels pool by max (any sybil window in the cell -> sybil) with the modal non-zero type.

Class coverage caveat (measured, not assumed)
---------------------------------------------
Types 5 and 6 (malicious RSU / malicious controller) produce ZERO vehicle-tier forgeries —
0.00% of their v2v beacons have real != claimed, because the malicious entity is an RSU or a
controller, not a vehicle claiming a false ID. Those runs are still included: they contribute
legitimate windows from a different attack context, which is exactly the negative evidence
that keeps the refit head from over-firing. But classes 5/6 get no positive support at this
tier and the refit head will never predict them — the same structural limit the July model
had (test support: malicious_controller 0, malicious_rsu 1262).

Run in ml/.venv:  python ml/refit/build_phi_dataset.py
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
_ML = _HERE.parent
sys.path.insert(0, str(_ML / "fusion"))
import identity_manifest as IDM                      # noqa: E402  (snap_grid, EXPORT_GRID_S)

KEY = ["run_id", "claimed_node_id", "window_start_seconds"]
DEF_OUT = _HERE / "outputs" / "phi_current.parquet"

# (run_dir, attack_type) — one attack type per run, verified from the log's attack_type column.
DEF_RUNS = [
    ("mock_ablation/sweep20s/type1", 1),                        # outsider
    ("mock_ablation/sweep20s/type2", 2),                        # sim
    ("mock_ablation/chanmode0_check/t3_22s_noair_CONTROL", 3),  # nonsim
    ("mock_ablation/chanmode0_check/t4_22s_noair_CONTROL", 4),  # indirect
    ("mock_ablation/sweep20s/type5", 5),                        # malicious_rsu   (0 veh-tier +)
    ("mock_ablation/sweep20s/type6", 6),                        # malicious_ctrl  (0 veh-tier +)
]


def _load_module(name, relpath):
    """Import a predictor module by path (they are not a package)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, _ML / relpath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def labelled_temporal_windows(gru_mod, predictor, run_dir, run_id, attack_type):
    """φ_temp + p_temp + the notebook's window labels, pooled to the 2 s grid.

    Mirrors predict.build_windows_live (same filter, dedup, grouping, windowing) and carries
    the per-beacon attack_type through so each window gets the notebook's label.
    """
    need = gru_mod.NEED_COLS | {"attack_type"}
    df = pd.read_csv(Path(run_dir) / "communication_log.csv",
                     usecols=lambda c: c in need)
    df = df[(df["flow"] == "v2v_beacon") & (df["receiver_role"] == "vehicle")].copy()
    if df.empty:
        return pd.DataFrame()
    df["run_id"] = run_id
    # notebook rule: a beacon is sybil iff the claimed ID differs from the real sender
    mismatch = (df["real_node_id"] != df["claimed_node_id"]).values
    df["at"] = np.where(mismatch, int(attack_type), 0).astype(np.int8)

    dup = (df.groupby(gru_mod.BEACON_KEY)["receiver_id"].nunique()
             .rename("observer_count").reset_index())
    df = df.merge(dup, on=gru_mod.BEACON_KEY, how="left")

    W, step = gru_mod.WINDOW_W, gru_mod.WINDOW_STEP
    Xs, Ls, meta = [], [], []
    for (run, rid, cid), g in df.sort_values("receive_time").groupby(
            ["run_id", "receiver_id", "claimed_node_id"], sort=False):
        if len(g) < W:
            continue
        g = g.reset_index(drop=True)
        delta_t = g["receive_time"].diff().fillna(0.0).values
        msg_delta = g["bsm_msg_count"].diff().fillna(0.0).values
        tid_chg = (g["bsm_temporary_id"] != g["bsm_temporary_id"].shift(1)
                   ).fillna(False).astype(float).values
        feat = np.column_stack([delta_t, tid_chg, g["bsm_x"].values, g["bsm_y"].values,
                                g["bsm_speed"].values, g["bsm_heading"].values,
                                g["packet_size"].values, g["delay"].values,
                                g["observer_count"].values, msg_delta]).astype(np.float32)
        tvec, atv = g["receive_time"].values, g["at"].values
        for s in range(0, len(feat) - W + 1, step):
            wt = atv[s:s + W]
            nz = wt[wt > 0]
            lab = int(pd.Series(nz).mode().iloc[0]) if len(nz) else 0
            Xs.append(feat[s:s + W])
            Ls.append(W)
            meta.append({"run_id": run, "claimed_node_id": cid,
                         "window_start_seconds": float(tvec[s]),
                         "attack_type": lab, "is_sybil": int(lab > 0)})
    if not Xs:
        return pd.DataFrame()

    X, L = np.stack(Xs), np.array(Ls, np.int32)
    phi, prob = predictor._extract_phi(predictor._scale(X), L)

    out = pd.DataFrame(meta)
    out["window_start_seconds"] = IDM.snap_grid(out["window_start_seconds"].to_numpy())
    for i in range(phi.shape[1]):
        out[f"phi_temp_{i}"] = phi[:, i]
    for k in range(prob.shape[1]):
        out[f"p_temp_{k}"] = prob[:, k]
    val = [c for c in out.columns if c.startswith(("phi_temp_", "p_temp_"))]
    # φ/p pool by mean (as deployed); labels pool by "any sybil -> modal non-zero type"
    pooled = out.groupby(KEY, as_index=False)[val].mean()
    lab = (out.groupby(KEY, as_index=False)
              .agg(is_sybil=("is_sybil", "max"),
                   attack_type=("attack_type", lambda s: int(s[s > 0].mode().iloc[0])
                                if (s > 0).any() else 0)))
    return pooled.merge(lab, on=KEY, how="left")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", default=str(DEF_OUT))
    ap.add_argument("--device", default="cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") != "" else "cpu")
    args = ap.parse_args()

    import torch
    dev = args.device if torch.cuda.is_available() and args.device == "cuda" else "cpu"

    gru_mod = _load_module("gru_predict", "analyzers/temporal_gru/predict.py")
    rssi_mod = _load_module("rssi_predict", "analyzers/rssi_cnn/predict.py")
    trust_mod = _load_module("trust_predict", "analyzers/vehicle_trust/predict.py")
    # ALWAYS the current (July) encoders — the refit reuses them frozen. Ignore any
    # SYBIL_GRU_MODEL_DIR override so building the dataset never depends on the switch.
    gru = gru_mod.TemporalPredictor.load(
        model_dir=gru_mod._HERE / "outputs" / "temporal_vehicle_tier", device=dev)
    rssi = rssi_mod.RSSIPredictor.load(device=dev)
    trust = trust_mod.TrustPredictor.load()
    print(f"[refit] encoders loaded on {dev} (frozen; only the heads get refit)\n")

    frames = []
    for rel, at in DEF_RUNS:
        run_dir = _ML.parent / rel
        if not (run_dir / "communication_log.csv").exists():
            print(f"[refit] SKIP (missing): {rel}")
            continue
        run_id = rel.replace("/", "__")
        t = labelled_temporal_windows(gru_mod, gru, run_dir, run_id, at)
        if t.empty:
            print(f"[refit] SKIP (no windows): {rel}")
            continue
        # optional blocks, left-joined onto the GRU anchor exactly like assemble_ci
        for mod_pred, name in ((rssi, "rssi"), (trust, "trust")):
            try:
                d = mod_pred.score_logs(str(run_dir), run_id=run_id)
            except Exception as e:                      # a missing optional log must not abort
                print(f"[refit]   {name} unavailable for {rel}: {type(e).__name__}: {e}")
                continue
            if d is None or d.empty:
                print(f"[refit]   {name} produced no rows for {rel}")
                continue
            new = [c for c in d.columns if c not in KEY and c not in t.columns]
            t = t.merge(d[KEY + new], on=KEY, how="left")
        frames.append(t)
        print(f"[refit] {rel:52s} rows={len(t):6d}  sybil={t.is_sybil.mean() * 100:5.1f}%  "
              f"types={sorted(t.attack_type.unique())}")

    if not frames:
        raise SystemExit("no runs produced windows")
    df = pd.concat(frames, ignore_index=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)

    print(f"\n[refit] TOTAL rows={len(df):,}  identities={df.claimed_node_id.nunique():,}")
    print("[refit] class balance:",
          df.attack_type.value_counts().sort_index().to_dict())
    for blk, col in (("phi_rssi", "phi_rssi_0"), ("phi_trust", "phi_trust_0")):
        cov = df[col].notna().mean() * 100 if col in df.columns else 0.0
        print(f"[refit] {blk:10s} coverage: {cov:5.1f}%")
    print(f"[refit] wrote {out}")


if __name__ == "__main__":
    main()
