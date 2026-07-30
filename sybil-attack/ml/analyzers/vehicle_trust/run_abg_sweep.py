#!/usr/bin/env python
"""(alpha, beta, gamma) sensitivity sweep for the composite trust score
(report Eq. trust_composite; supervisor Gap 6).

The three composite weights were never swept: `DEFAULT_HP` fixes them at
(0.4, 0.3, 0.3). This script fills that gap WITHOUT retraining phi_trust and
WITHOUT re-running the simulator, by exploiting the dependency structure of
`trust_v2_lib.add_trust_scores`:

  * T_behav = exp(-lam * rate_deviation)          -> independent of alpha/beta/gamma
  * T_RSSI  = 1 - raw_coloc_mean (0.5 if unseen)  -> independent of alpha/beta/gamma
  * T_composite / T_hist                          -> the ONLY weight-dependent terms

So the cached W=10 windows (which already store raw [0,1] T_RSSI / T_behav /
rsu_verified_prob) are sufficient: for each candidate weighting we simply re-run
the Eq. 3.25 recursion and re-score. No window rebuild (the ~48 min step), no FL.

Evaluation matches the Table 4.3 harness: group-aware 5-fold CV over the
train+val identities (test never touched), same shuffle seed, same fold split.
Because nothing is trained here, the reported quantity is the *discriminability
of the composite score itself*:

  * AUC            -- threshold-free, computed on the held-out fold
  * MCC            -- threshold chosen on the fold's TRAINING complement, then
                      applied to the held-out fold (no threshold leakage)

Writes: outputs/trust_sensitivity_abg.csv       (per-fold rows)
        outputs/trust_sensitivity_abg_summary.csv (mean/std per weighting)
"""
import sys, time
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, matthews_corrcoef

LIB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LIB_DIR))
import trust_v2_lib as T

CACHE = LIB_DIR / "cache" / "windows_shared.parquet"   # deployed W = 10
OUT   = LIB_DIR / "outputs"
SEED  = T.RNG_SEED
K     = 5

# deployed setting first, then the supervisor's four-point grid
GRID = [
    (0.40, 0.30, 0.30),          # deployed (DEFAULT_HP)
    (1 / 3, 1 / 3, 1 / 3),
    (0.50, 0.25, 0.25),
    (0.25, 0.50, 0.25),
    (0.25, 0.25, 0.50),
]
MU  = T.DEFAULT_HP["mu"]         # 0.3, held constant (this is an OFAT sweep)


def recompute_composite(gid, T_rssi, T_behav, boot, alpha, beta, gamma, mu):
    """Vectorised-loop replica of add_trust_scores' Eq. 3.25 recursion.

    `gid` must be the contiguous group id of (run_id, observer, claimed) over rows
    already sorted by (that key, window_start). Returns (T_composite, T_hist).

    Note the clip in the library is a no-op here: with T_RSSI, T_behav, t_prev in
    [0,1] the numerator is bounded by alpha+beta+gamma*mu = denom, so t_now in [0,1].
    """
    denom = 1.0 - gamma * (1.0 - mu)
    n = len(gid)
    comp = np.empty(n); hist = np.empty(n)
    prev = {}
    for i in range(n):
        k = gid[i]
        t_prev = prev.get(k)
        if t_prev is None:
            t_prev = boot[i]
        t_now = (alpha * T_rssi[i] + beta * T_behav[i] + gamma * mu * t_prev) / denom
        if t_now < 0.0:
            t_now = 0.0
        elif t_now > 1.0:
            t_now = 1.0
        comp[i] = t_now
        h = mu * t_prev + (1.0 - mu) * t_now
        hist[i] = 0.0 if h < 0.0 else (1.0 if h > 1.0 else h)
        prev[k] = t_now
    return comp, hist


def best_threshold(score, y, n_q=199):
    """MCC-maximising threshold, searched over score quantiles."""
    qs = np.quantile(score, np.linspace(0.005, 0.995, n_q))
    qs = np.unique(qs)
    best_t, best_m = qs[0], -2.0
    for t in qs:
        m = matthews_corrcoef(y, (score >= t).astype(np.int8))
        if m > best_m:
            best_t, best_m = t, m
    return float(best_t), float(best_m)


def main():
    t0 = time.time()
    cols = ["run_id", "observer_vehicle_id", "observed_claimed_id", "observed_real_id",
            "window_start", "attack_percentage", "attack_type", "T_RSSI", "T_behav",
            "T_composite", "rsu_verified_prob", "label", "group_key"]
    print(f"[{time.strftime('%H:%M:%S')}] loading {CACHE.name} ...", flush=True)
    w = pd.read_parquet(CACHE, columns=cols)
    print(f"  {len(w):,} windows | pos_rate={w['label'].mean():.4f}", flush=True)

    # Same shared identity split as every other trust experiment; test is never touched.
    w = T.group_stratified_split(w)
    pool = w[w["split"].isin(["train", "val"])].copy()
    del w
    print(f"  train+val pool: {len(pool):,} windows | pos_rate={pool['label'].mean():.4f}",
          flush=True)

    # Sort exactly as add_trust_scores does, then build contiguous group ids.
    pool = pool.sort_values(["run_id", "observer_vehicle_id",
                             "observed_claimed_id", "window_start"]).reset_index(drop=True)
    gid = pd.factorize(pd.Series(list(zip(pool["run_id"], pool["observer_vehicle_id"],
                                          pool["observed_claimed_id"]))))[0]
    T_rssi = pool["T_RSSI"].to_numpy(float)
    T_beh  = pool["T_behav"].to_numpy(float)
    vp     = pool["rsu_verified_prob"].to_numpy(float)
    boot   = np.where(np.isfinite(vp), vp, 0.5)
    y      = pool["label"].to_numpy().astype(np.int8)
    print(f"  {gid.max() + 1:,} (run, observer, claimed) chains", flush=True)

    # Table 4.3's fold construction, verbatim.
    groups = pd.Series(pool["group_key"].dropna().unique())
    groups = groups.sample(frac=1.0, random_state=SEED).to_numpy()
    fold_groups = np.array_split(groups, K)
    gk = pool["group_key"].to_numpy()

    rows = []
    for (a, b, g) in GRID:
        assert abs(a + b + g - 1.0) < 1e-6
        tag = f"({a:.2f},{b:.2f},{g:.2f})"
        ts = time.time()
        comp, _hist = recompute_composite(gid, T_rssi, T_beh, boot, a, b, g, MU)
        # sanity: the deployed weighting must reproduce the cached column
        if abs(a - 0.40) < 1e-9 and abs(b - 0.30) < 1e-9:
            d = np.abs(comp - pool["T_composite"].to_numpy(float)).max()
            print(f"  [check] deployed weighting reproduces cached T_composite, "
                  f"max|diff|={d:.3e}", flush=True)
        for i in range(K):
            in_val = np.isin(gk, fold_groups[i])
            s_tr, y_tr = comp[~in_val], y[~in_val]
            s_va, y_va = comp[in_val], y[in_val]
            thr, mcc_tr = best_threshold(s_tr, y_tr)
            mcc_va = matthews_corrcoef(y_va, (s_va >= thr).astype(np.int8))
            auc_va = roc_auc_score(y_va, s_va)
            rows.append(dict(alpha=a, beta=b, gamma=g, fold=i,
                             n_val=int(in_val.sum()), pos_rate=float(y_va.mean()),
                             thr=thr, mcc_train=mcc_tr, mcc_val=mcc_va, auc_val=auc_va))
            print(f"  {tag} fold {i}: AUC={auc_va:.4f} MCC={mcc_va:.4f} "
                  f"(thr={thr:.4f}, n={in_val.sum():,})", flush=True)
        print(f"  {tag} done in {time.time() - ts:.0f}s", flush=True)

    df = pd.DataFrame(rows)
    OUT.mkdir(exist_ok=True)
    df.to_csv(OUT / "trust_sensitivity_abg.csv", index=False)

    summ = (df.groupby(["alpha", "beta", "gamma"], sort=False)
              .agg(auc_mean=("auc_val", "mean"), auc_std=("auc_val", "std"),
                   mcc_mean=("mcc_val", "mean"), mcc_std=("mcc_val", "std"))
              .reset_index())
    summ["deployed"] = np.isclose(summ.alpha, 0.40) & np.isclose(summ.beta, 0.30)
    summ.to_csv(OUT / "trust_sensitivity_abg_summary.csv", index=False)

    print("\n=== (alpha,beta,gamma) sensitivity — composite score, 5-fold grouped CV ===")
    print(f"{'(a,b,g)':>22s} {'AUC':>16s} {'MCC':>16s}")
    for _, r in summ.iterrows():
        tag = f"({r.alpha:.2f},{r.beta:.2f},{r.gamma:.2f})" + (" *" if r.deployed else "")
        print(f"{tag:>22s} {r.auc_mean:8.4f}±{r.auc_std:.4f} {r.mcc_mean:8.4f}±{r.mcc_std:.4f}")
    print(f"\nAUC span across grid: {summ.auc_mean.max() - summ.auc_mean.min():.4f}")
    print(f"MCC span across grid: {summ.mcc_mean.max() - summ.mcc_mean.min():.4f}")
    print(f"total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
