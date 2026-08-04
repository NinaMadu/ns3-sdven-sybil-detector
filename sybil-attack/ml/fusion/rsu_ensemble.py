"""
Eq 3.19 / Eq 3.20 — RSU-tier ensemble score ŷ_ens.

    Eq 3.19:  p̄_temp = 1 − P_XGB,temp(legit)      p̄_rssi = 1 − P_XGB,rssi(legit)
    Eq 3.20:  ŷ_ens  = λ1·ŷ_i + λ2·p̄_temp + λ3·p̄_rssi ,   Σλ = 1

Grid-searches λ_k ∈ {0.2, 0.3, 0.4, 0.5} subject to λ1+λ2+λ3 = 1, and keeps the
combination that maximises validation binary-MCC (decision cut swept per combo).
ŷ_ens replaces ŷ_i as the detection signal passed into the LLM agent context
(Eq 3.21).

Three evidence streams (all keyed on the run-scoped JOIN_KEY):
  ŷ_i     = y_hat_i_fused    (fusion_head.parquet,  Eq 3.18 head, this repo)
  p̄_temp  = p_bar_temp       (temporal_xgb_rsu.parquet)
  p̄_rssi  = p_bar_rssi       (rssi_xgb_rsu.parquet)

The RSU XGB exports cover fewer windows than the vehicle-tier spine; when a p̄
term is absent for a window the combination is renormalised over the terms that
are present (weights rescaled to sum 1), so ŷ_ens stays in [0,1] and coverage
tracks the ŷ_i spine.

Output: notebooks/outputs/ensemble_yhat.parquet  (JOIN_KEY + y_hat_ens + terms)
        notebooks/outputs/ensemble_lambdas.json

Run in ml/.venv:  python ml/fusion/rsu_ensemble.py
"""

import argparse
import itertools
import json
import os
import sys

import numpy as np
import pandas as pd

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "llm", "common"))
import constants as C  # noqa: E402

from sklearn.metrics import matthews_corrcoef  # noqa: E402

FUSION = os.path.join(C.OUTPUTS_DIR, "fusion_head.parquet")
TEMP_XGB = C.RSU_TEMPORAL_XGB
RSSI_XGB = C.RSU_RSSI_XGB
DEF_OUT = os.path.join(C.OUTPUTS_DIR, "ensemble_yhat.parquet")
DEF_LAM = os.path.join(C.OUTPUTS_DIR, "ensemble_lambdas.json")

LAMBDA_GRID = [0.2, 0.3, 0.4, 0.5]
TERMS = ["y_hat_i_fused", "p_bar_temp", "p_bar_rssi"]   # ŷ_i, p̄_temp, p̄_rssi


def _label_from(df):
    """spine carries is_sybil + split; pull them from the fusion head's source c_i."""
    ci = pd.read_parquet(os.path.join(_HERE, "..", "llm", "common", "context", "c_i.parquet"),
                         columns=C.JOIN_KEY + ["is_sybil"])
    return df.merge(ci, on=C.JOIN_KEY, how="left")


def weighted_score(mat, lam):
    """mat: (n,3) with NaN where a term is absent. lam: (3,). Renormalise over present."""
    w = np.where(np.isnan(mat), 0.0, np.asarray(lam)[None, :])
    denom = w.sum(axis=1)
    num = np.nansum(np.where(np.isnan(mat), 0.0, mat) * w, axis=1)
    out = np.divide(num, denom, out=np.full(len(mat), np.nan), where=denom > 0)
    return out


def best_cut_mcc(score, y):
    m = ~np.isnan(score)
    s, yy = score[m], y[m]
    if len(np.unique(yy)) < 2:
        return 0.5, 0.0
    best_c, best_m = 0.5, -1.0
    for c in np.linspace(0.1, 0.9, 33):
        mcc = matthews_corrcoef(yy, (s >= c).astype(int))
        if mcc > best_m:
            best_c, best_m = c, mcc
    return best_c, best_m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEF_OUT)
    ap.add_argument("--lambdas", default=DEF_LAM)
    args = ap.parse_args()

    fh = pd.read_parquet(FUSION)                                   # ŷ_i spine
    tx = pd.read_parquet(TEMP_XGB)[C.JOIN_KEY + ["p_bar_temp"]]
    rx = pd.read_parquet(RSSI_XGB)[C.JOIN_KEY + ["p_bar_rssi"]]

    # p_bar_temp: nearest-window join per (run_id, attack_percentage,
    # claimed_node_id, split), tolerance = one window step either side.
    # Investigated as a hypothesized "cadence mismatch" bug — it isn't one:
    # both tables already sit on the identical 2s grid (verified directly
    # against the parquet files). The real reason most windows lack an
    # exact match is that 42% of vehicle-tier identities are NEVER observed
    # by ANY RSU for the whole run (a physical RSU-coverage limit, the same
    # phenomenon behind the Q32 revocation-bulletin coverage gap) — no join
    # logic can manufacture a signal the RSU tier never received. Even an
    # unlimited-tolerance nearest match only reaches 77.6% for that reason;
    # tolerance is capped at one window step so this only ever borrows an
    # ADJACENT real observation of the same identity, never a stale one
    # from a different part of the run.
    by_cols = [c for c in C.JOIN_KEY if c != "window_start_seconds"]
    tx_sorted = tx.sort_values("window_start_seconds")
    fh_sorted = fh.sort_values("window_start_seconds")
    fh_with_tx = pd.merge_asof(
        fh_sorted, tx_sorted, on="window_start_seconds", by=by_cols,
        direction="nearest", tolerance=2.0)
    ev = fh_with_tx.merge(rx, on=C.JOIN_KEY, how="left")
    ev = _label_from(ev)
    for t in TERMS:
        cov = ev[t].notna().mean() * 100
        print(f"  term {t:14s} coverage: {cov:5.1f}%")

    mat = ev[TERMS].values.astype(float)
    y = ev["is_sybil"].values.astype(int)
    val = ev["split"].values == "val"
    test = ev["split"].values == "test"

    # grid search λ over the simplex {0.2,0.3,0.4,0.5}^3 with Σλ=1
    combos = [c for c in itertools.product(LAMBDA_GRID, repeat=3) if abs(sum(c) - 1.0) < 1e-9]
    best = None
    for lam in combos:
        score = weighted_score(mat, lam)
        cut, _ = best_cut_mcc(score[val], y[val])
        vm = matthews_corrcoef(y[val][~np.isnan(score[val])],
                               (score[val][~np.isnan(score[val])] >= cut).astype(int))
        if best is None or vm > best["val_mcc"]:
            best = {"lambda": {"lambda1_yhat_i": lam[0], "lambda2_pbar_temp": lam[1],
                              "lambda3_pbar_rssi": lam[2]}, "cut": float(cut), "val_mcc": float(vm)}
    lam = (best["lambda"]["lambda1_yhat_i"], best["lambda"]["lambda2_pbar_temp"],
           best["lambda"]["lambda3_pbar_rssi"])
    score = weighted_score(mat, lam)

    # report chosen combo vs each single term (test)
    def mcc_at(s, cut, mask):
        mm = mask & ~np.isnan(s)
        return matthews_corrcoef(y[mm], (s[mm] >= cut).astype(int))
    print(f"\nchosen λ={lam} Σ={sum(lam):.1f}  cut={best['cut']:.3f}  val-MCC={best['val_mcc']:.4f}")
    print(f"  ŷ_ens   test-MCC = {mcc_at(score, best['cut'], test):.4f}")
    for i, t in enumerate(TERMS):
        c, _ = best_cut_mcc(mat[val, i], y[val])
        print(f"  {t:14s} test-MCC = {mcc_at(mat[:, i], c, test):.4f} (own cut {c:.2f})")

    out = ev[C.JOIN_KEY].copy()
    out["y_hat_ens"] = score
    for t in TERMS:
        out[t] = ev[t].values
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    out.to_parquet(args.out, index=False)
    json.dump(best, open(args.lambdas, "w"), indent=2)
    print(f"\nwrote {out.shape} -> {args.out}\n       λ/cut -> {args.lambdas}")
    print(f"  ŷ_ens coverage on spine: {out['y_hat_ens'].notna().mean()*100:.1f}%")


if __name__ == "__main__":
    main()
