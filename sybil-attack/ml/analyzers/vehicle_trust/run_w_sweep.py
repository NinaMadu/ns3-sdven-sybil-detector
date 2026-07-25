#!/usr/bin/env python
"""Standalone W (sliding-window) sweep for the Trust Analyzer sensitivity analysis
(report Table 4.3, 8th axis). Replicates the notebook Section 8.1 harness verbatim so
results are directly comparable to trust_sensitivity_table_4_3.csv (the 7 non-window
axes). Grid chosen 2026-07-25: W in {3, 5, 10, 20} -- report's {5,10,20} plus W=3 for
the small-window (low OBU latency/memory) emphasis. W=10 reuses the existing cache;
W=3/5/20 rebuild windows from the raw logs (I/O-bound, slow first run -> tmux).

Writes: outputs/trust_sensitivity_W.csv
"""
import sys, time
from pathlib import Path
import numpy as np, pandas as pd

LIB_DIR = Path(__file__).resolve().parent          # ml/analyzers/vehicle_trust
sys.path.insert(0, str(LIB_DIR))
import trust_v2_lib as T

CACHE = LIB_DIR / "cache" / "windows_shared.parquet"   # existing W=10 cache
NF    = len(T.FEATURE_COLS)

# ── harness identical to notebook cell 8.1 ─────────────────────────────────────
CV_FOLDS         = 5
CV_ROUNDS        = 12
CV_PATIENCE      = 4
TUNE_SEL_FRAC    = 0.20
TUNE_MAX_WINDOWS = 1_000_000
SEED             = T.RNG_SEED

BASE = dict(hidden1=32, hidden2=16, dropout=0.1, local_lr=0.05, batch_size=32,
            local_epochs=3, fedprox_mu=0.001, dp_sigma=0.1, trim_k=1)

def _cap_clients(df, max_rows, seed):
    if not max_rows or len(df) <= max_rows:
        return df
    cid = df["run_id"].astype(str) + "#" + df["observer_vehicle_id"].astype(str)
    sizes = cid.value_counts()
    r = np.random.default_rng(seed)
    ids = r.permutation(sizes.index.to_numpy())
    keep, tot = [], 0
    for c in ids:
        keep.append(c); tot += int(sizes[c])
        if tot >= max_rows:
            break
    return df[cid.isin(set(keep))]

def precompute_folds(pool, k, max_windows, seed=SEED):
    groups = pd.Series(pool["group_key"].dropna().unique())
    groups = groups.sample(frac=1.0, random_state=seed).to_numpy()
    fold_groups = np.array_split(groups, k)
    folds = []
    for i in range(k):
        held = set(fold_groups[i])
        in_val = pool["group_key"].isin(held)
        tr_raw = _cap_clients(pool[~in_val], max_windows, seed + i)
        va_raw = pool[in_val]
        d = pd.concat([tr_raw.assign(split="train"), va_raw.assign(split="val")], ignore_index=True)
        d, _ = T.prep_features(d)
        ftr, fva = d[d.split == "train"], d[d.split == "val"]
        pr = ftr["label"].mean()
        pw = float(np.clip((1 - pr) / max(pr, 1e-6), 1.0, 20.0))
        folds.append((ftr, fva, pw))
        print(f"  fold {i}: train={len(ftr):,} ({tr_raw['run_id'].nunique()} runs) "
              f"val={len(fva):,}  pos_rate={pr:.3f}  pw={pw:.2f}", flush=True)
    return folds

def cv_mcc(hp, folds, rounds=CV_ROUNDS, patience=CV_PATIENCE, sel_frac=TUNE_SEL_FRAC):
    mccs = []
    for ftr, fva, pw in folds:
        warm = T.centralized_pretrain(ftr, T.FEATURE_COLS, NF, epochs=2, pos_weight=pw,
                                      hidden1=hp.get("hidden1", 32), hidden2=hp.get("hidden2", 16),
                                      dropout=hp.get("dropout", 0.1))
        _, _, best = T.train_fl(ftr, fva, T.FEATURE_COLS, hp, NF, max_rounds=rounds,
                                patience=patience, pos_weight=pw, warm_start=warm,
                                sel_frac=sel_frac, min_clients=8, verbose=False)
        mccs.append(best)
    return float(np.mean(mccs)), float(np.std(mccs))

def n_params(h1, h2, nf=None):
    nf = nf or NF
    return nf * h1 + h1 + h1 * h2 + h2 + h2 * 1 + 1

# ── W sweep ────────────────────────────────────────────────────────────────────
W_GRID  = [3, 5, 10, 20]
W_CACHE = {3:  LIB_DIR / "cache" / "windows_shared_W3.parquet",
           5:  LIB_DIR / "cache" / "windows_shared_W5.parquet",
           10: CACHE,                                              # existing W=10 cache
           20: LIB_DIR / "cache" / "windows_shared_W20.parquet"}

print(f"[{time.strftime('%H:%M:%S')}] W sweep start | grid={W_GRID} | "
      f"NF={NF} | folds={CV_FOLDS} rounds={CV_ROUNDS}", flush=True)
t0 = time.time()
records = []
for W in W_GRID:
    tw = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] ===== W = {W} =====", flush=True)
    raw_w = T.build_pipeline(window_w=W, cache=str(W_CACHE[W]))      # builds or loads
    raw_w = T.group_stratified_split(raw_w)
    pool_w = raw_w[raw_w.split.isin(["train", "val"])].copy()
    print(f"  pool={len(pool_w):,} windows | pos_rate={pool_w['label'].mean():.3f} "
          f"| build+load {time.time()-tw:.0f}s", flush=True)
    folds_w = precompute_folds(pool_w, CV_FOLDS, TUNE_MAX_WINDOWS)
    m, s = cv_mcc(BASE, folds_w)
    records.append({"axis": "W", "value": W, "cv_mcc": m, "cv_std": s,
                    "n_params": n_params(BASE["hidden1"], BASE["hidden2"]),
                    "dp_sigma": BASE["dp_sigma"], "is_anchor": (W == 10)})
    print(f"  W = {W:2d}  cv_mcc={m:.4f} +/- {s:.4f}   [{time.time()-tw:.0f}s]", flush=True)

    # incremental write so partial results survive an interruption
    out = LIB_DIR / "outputs" / "trust_sensitivity_W.csv"
    pd.DataFrame(records).to_csv(out, index=False)

w_df = pd.DataFrame(records)
print(f"\n[{time.strftime('%H:%M:%S')}] DONE in {time.time()-t0:.0f}s")
print(w_df.to_string(index=False))
print(f"wrote {LIB_DIR / 'outputs' / 'trust_sensitivity_W.csv'}", flush=True)
