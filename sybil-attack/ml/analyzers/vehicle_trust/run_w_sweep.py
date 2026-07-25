#!/usr/bin/env python
"""Standalone W (sliding-window) sweep for the Trust Analyzer sensitivity analysis
(report Table 4.3, 8th axis). Replicates the notebook Section 8.1 harness so results are
directly comparable to trust_sensitivity_table_4_3.csv (the 7 non-window axes). Grid
2026-07-25: W in {3, 5, 10, 20} -- report's {5,10,20} plus W=3 for the small-window
(low OBU latency/memory) emphasis.

MEMORY-SAFE rewrite (2026-07-25): the first attempt froze the machine because the small
windows blow up the row count (W=3 -> 21.7M windows, ~3.4x W=10) and the original
precompute_folds materialised ALL 5 standardised folds in memory at once (val uncapped)
-> exceeded 61GB RAM -> swap thrash -> freeze. This version instead:
  * streams folds one at a time: build ONE fold -> train -> record MCC -> free it, so
    resident memory is ~1 fold, not 5;
  * downcasts feature columns to float32 (halves the frame size);
  * reuses cached windows (W=3 already built -> windows_shared_W3.parquet; W=10 -> the
    existing cache), so only W=5 / W=20 are rebuilt from the raw logs.
Run under a systemd MemoryMax guard (see relaunch command) so any residual runaway is
killed cleanly instead of freezing the box.

Writes: outputs/trust_sensitivity_W.csv (incremental per W).
"""
import sys, time, gc
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

def _build_fold(pool, fold_groups, i, max_windows, seed=SEED):
    """Build a SINGLE fold's leakage-free, float32 (train, val, pos_weight)."""
    held = set(fold_groups[i])
    in_val = pool["group_key"].isin(held)
    tr_raw = _cap_clients(pool[~in_val], max_windows, seed + i)
    va_raw = pool[in_val]
    d = pd.concat([tr_raw.assign(split="train"), va_raw.assign(split="val")], ignore_index=True)
    d, _ = T.prep_features(d)                      # fits on split=='train' only (no leakage)
    for c in T.FEATURE_COLS:                        # halve memory: float64 -> float32
        if c in d.columns:
            d[c] = d[c].astype("float32")
    ftr = d[d.split == "train"].copy()
    fva = d[d.split == "val"].copy()
    pr = ftr["label"].mean()
    pw = float(np.clip((1 - pr) / max(pr, 1e-6), 1.0, 20.0))
    del d, tr_raw, va_raw, in_val
    gc.collect()
    return ftr, fva, pw

def cv_mcc(hp, pool, k=CV_FOLDS, max_windows=TUNE_MAX_WINDOWS, rounds=CV_ROUNDS,
           patience=CV_PATIENCE, sel_frac=TUNE_SEL_FRAC, seed=SEED):
    """Streaming k-fold CV MCC: one fold resident at a time (build->train->free)."""
    groups = pd.Series(pool["group_key"].dropna().unique())
    groups = groups.sample(frac=1.0, random_state=seed).to_numpy()
    fold_groups = np.array_split(groups, k)
    mccs = []
    for i in range(k):
        ftr, fva, pw = _build_fold(pool, fold_groups, i, max_windows, seed)
        print(f"  fold {i}: train={len(ftr):,} val={len(fva):,} "
              f"pos_rate={ftr['label'].mean():.3f} pw={pw:.2f}", flush=True)
        warm = T.centralized_pretrain(ftr, T.FEATURE_COLS, NF, epochs=2, pos_weight=pw,
                                      hidden1=hp.get("hidden1", 32), hidden2=hp.get("hidden2", 16),
                                      dropout=hp.get("dropout", 0.1))
        _, _, best = T.train_fl(ftr, fva, T.FEATURE_COLS, hp, NF, max_rounds=rounds,
                                patience=patience, pos_weight=pw, warm_start=warm,
                                sel_frac=sel_frac, min_clients=8, verbose=False)
        mccs.append(best)
        print(f"    fold {i} MCC={best:.4f}", flush=True)
        del ftr, fva, warm            # free this fold before building the next
        gc.collect()
    return float(np.mean(mccs)), float(np.std(mccs))

def n_params(h1, h2, nf=None):
    nf = nf or NF
    return nf * h1 + h1 + h1 * h2 + h2 + h2 * 1 + 1

# ── W sweep ────────────────────────────────────────────────────────────────────
W_GRID  = [3, 5, 10, 20]
W_CACHE = {3:  LIB_DIR / "cache" / "windows_shared_W3.parquet",   # already built
           5:  LIB_DIR / "cache" / "windows_shared_W5.parquet",   # rebuilt from logs
           10: CACHE,                                             # existing W=10 cache
           20: LIB_DIR / "cache" / "windows_shared_W20.parquet"}  # rebuilt from logs

print(f"[{time.strftime('%H:%M:%S')}] W sweep start (mem-safe/streaming) | grid={W_GRID} | "
      f"NF={NF} | folds={CV_FOLDS} rounds={CV_ROUNDS}", flush=True)
t0 = time.time()
records = []
for W in W_GRID:
    tw = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] ===== W = {W} =====", flush=True)
    raw_w = T.build_pipeline(window_w=W, cache=str(W_CACHE[W]))      # loads cache or builds
    raw_w = T.group_stratified_split(raw_w)
    pool_w = raw_w[raw_w.split.isin(["train", "val"])].copy()
    del raw_w; gc.collect()
    print(f"  pool={len(pool_w):,} windows | pos_rate={pool_w['label'].mean():.3f} "
          f"| build+load {time.time()-tw:.0f}s", flush=True)
    m, s = cv_mcc(BASE, pool_w)
    del pool_w; gc.collect()
    records.append({"axis": "W", "value": W, "cv_mcc": m, "cv_std": s,
                    "n_params": n_params(BASE["hidden1"], BASE["hidden2"]),
                    "dp_sigma": BASE["dp_sigma"], "is_anchor": (W == 10)})
    print(f"  W = {W:2d}  cv_mcc={m:.4f} +/- {s:.4f}   [{time.time()-tw:.0f}s]", flush=True)

    # incremental write so partial results survive an interruption
    pd.DataFrame(records).to_csv(LIB_DIR / "outputs" / "trust_sensitivity_W.csv", index=False)

w_df = pd.DataFrame(records)
print(f"\n[{time.strftime('%H:%M:%S')}] DONE in {time.time()-t0:.0f}s")
print(w_df.to_string(index=False))
print(f"wrote {LIB_DIR / 'outputs' / 'trust_sensitivity_W.csv'}", flush=True)
