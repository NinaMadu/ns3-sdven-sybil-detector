"""
Shared fusion spine for the three vehicle-tier v2 models
(RSSI CNN · temporal GRU · trust MLP).

Guarantees all three train/export on:
  1. the SAME identity subsample   (KEEP_FRAC of claimed ids per run, one seeded draw),
  2. the SAME leakage-safe split    (grouped by real vehicle, not claimed id),
  3. the SAME time grid             (window_start_seconds snapped to EXPORT_GRID_S),
so their phi tables inner-join cleanly on
  (run_id, claimed_node_id, window_start_seconds, split)
for the Eq 3.18 fusion head and the Eq 3.31 context assembler.

This is the SINGLE SOURCE OF TRUTH. Each notebook does:

    import sys; sys.path.insert(0, ".../ml/fusion")
    from identity_manifest import (load_manifest, keep_mask, attach_split,
                                    snap_grid, RUN_DIRS, EXPORT_GRID_S,
                                    ATTACK_CLASSES, ARTIFACTS_DIR)
    man = load_manifest()                       # builds split_map.parquet once
    df  = df[keep_mask(df, man)]                 # keep the shared identity subsample
    df  = attach_split(df, man)                  # adds a leakage-safe 'split' column
    ... train on df ...
    export["window_start_seconds"] = snap_grid(export["window_start_seconds"])

The split is built from the authoritative communication_log (ground-truth
real_node_id + attack_type_label), so every model inherits an identical split
regardless of which per-model log it actually reads.
"""

import glob
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

# ── locations ───────────────────────────────────────────────────────────────
_HERE     = Path(__file__).resolve().parent
BASE_DIR  = _HERE.parent.parent                      # .../ns-3.35/sybil-attack
DATA_ROOT = BASE_DIR / "datasets"
# reorganized tree: fusion intermediates in ml/fusion/outputs, spine in ml/fusion/spine
ARTIFACTS_DIR = BASE_DIR / "ml" / "fusion" / "outputs"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
SPLIT_MAP_PATH = BASE_DIR / "ml" / "fusion" / "spine" / "split_map.parquet"

# ── the attacker-percentage sweep (the three focus runs) ────────────────────
_SWEEP_PARENTS = [
    DATA_ROOT / "seq6_pct_sweep_20260709_023108",   # pct20_s1, pct40_s1
    DATA_ROOT / "seq6_pct_sweep_20260708_101653",   # pct100_s1
]
RUN_DIRS = sorted(
    str(d) for parent in _SWEEP_PARENTS
    for d in glob.glob(str(parent / "pct*_s1"))
)

# ── shared knobs (edit HERE only) ───────────────────────────────────────────
KEEP_FRAC     = 0.4     # fraction of claimed identities kept per run (the "portion")
SEED          = 42
VAL_FRAC      = 0.15
TEST_FRAC     = 0.15
EXPORT_GRID_S = 2.0     # snap window_start_seconds to this grid at export (RSU 2s step)

# ── 7-class taxonomy (index == attack_type) ─────────────────────────────────
ATTACK_CLASSES = ["legitimate", "outsider", "sim", "nonsim", "indirect",
                  "malicious_rsu", "malicious_controller"]
N_CLASSES = len(ATTACK_CLASSES)

_COMM_COLS = ["real_node_id", "claimed_node_id", "attack_type_label"]


# ════════════════════════════════════════════════════════════════════════════
# Build
# ════════════════════════════════════════════════════════════════════════════
def _run_meta(run_dir):
    return json.load(open(os.path.join(run_dir, "run_meta.json")))


def _identity_table(run_dir, chunksize=5_000_000, nrows=None):
    """One row per claimed_node_id seen in this run's communication_log:
    real_vehicle (dominant real_node_id), is_sybil (any claimed!=real),
    attack_type (dominant phase type among its sybil beacons, else 0).
    Chunked so peak memory stays bounded on the multi-GB logs."""
    comm = os.path.join(run_dir, "communication_log.csv")
    # per-claimed accumulators
    real_counts = {}   # claimed -> {real: count}
    type_counts = {}   # claimed -> {atype: count}  (mismatched beacons only)
    seen_mism   = {}   # claimed -> bool
    read = 0
    for chunk in pd.read_csv(comm, usecols=_COMM_COLS, chunksize=chunksize):
        if nrows is not None:
            chunk = chunk.iloc[: max(0, nrows - read)]
            read += len(chunk)
        c = chunk["claimed_node_id"].to_numpy()
        r = chunk["real_node_id"].to_numpy()
        a = chunk["attack_type_label"].to_numpy()
        mism = r != c
        # dominant real vehicle per claimed
        for cc, rr in zip(c, r):
            d = real_counts.setdefault(int(cc), {})
            d[int(rr)] = d.get(int(rr), 0) + 1
        # dominant attack type among mismatched beacons
        for cc, aa in zip(c[mism], a[mism]):
            d = type_counts.setdefault(int(cc), {})
            d[int(aa)] = d.get(int(aa), 0) + 1
        for cc in c[mism]:
            seen_mism[int(cc)] = True
        if nrows is not None and read >= nrows:
            break

    rows = []
    for cc, rmap in real_counts.items():
        real_v = max(rmap, key=rmap.get)
        is_syb = int(seen_mism.get(cc, False))
        if is_syb and cc in type_counts:
            atype = max(type_counts[cc], key=type_counts[cc].get)
        else:
            atype = 0
        rows.append((cc, real_v, is_syb, int(atype)))
    return pd.DataFrame(rows, columns=["claimed_node_id", "real_vehicle",
                                       "is_sybil", "attack_type"])


def _group_stratified_split(vehicles, strata, val=VAL_FRAC, test=TEST_FRAC, seed=SEED):
    """Assign each vehicle (group) to train/val/test within its stratum.
    Returns dict vehicle_key -> split."""
    rng = np.random.default_rng(seed)
    assign = {}
    df = pd.DataFrame({"veh": vehicles, "stratum": strata}).drop_duplicates("veh")
    for _, sdf in df.groupby("stratum"):
        vs = sdf["veh"].to_numpy().copy()
        rng.shuffle(vs)
        n = len(vs)
        n_test = int(round(n * test))
        n_val  = int(round(n * val))
        for v in vs[:n_test]:               assign[v] = "test"
        for v in vs[n_test:n_test + n_val]: assign[v] = "val"
        for v in vs[n_test + n_val:]:       assign[v] = "train"
    return assign


def build_manifest(nrows=None, verbose=True):
    """Build the shared split_map from all runs' communication_logs and persist it."""
    parts = []
    for rd in RUN_DIRS:
        meta = _run_meta(rd)
        pct  = int(meta["sybil_attack_percentage"])
        run_id = str(meta.get("run_id", os.path.basename(rd)))
        tab = _identity_table(rd, nrows=nrows)

        # leakage-safe subsample: keep a fraction of CLAIMED identities per run
        rng = np.random.default_rng(SEED)
        ids = np.sort(tab["claimed_node_id"].to_numpy())
        keep = rng.choice(ids, size=max(1, int(len(ids) * KEEP_FRAC)), replace=False)
        tab = tab[tab["claimed_node_id"].isin(set(keep))].copy()

        tab["run_id"] = run_id
        tab["attack_percentage"] = pct
        tab["vehicle_key"] = run_id + "__vid" + tab["real_vehicle"].astype(str)
        parts.append(tab)
        if verbose:
            print(f"  {run_id:>10} pct{pct:>3}: {len(tab):>5} kept ids / {len(ids):>5} "
                  f"| sybil ids {int(tab.is_sybil.sum()):>5} | vehicles {tab.vehicle_key.nunique():>4}")

    man = pd.concat(parts, ignore_index=True)

    # split by VEHICLE within (attack_percentage, vehicle-is-attacker) strata
    veh = (man.groupby("vehicle_key")
              .agg(attack_percentage=("attack_percentage", "first"),
                   is_attacker=("is_sybil", "max"))
              .reset_index())
    strata = veh["attack_percentage"].astype(str) + "_a" + veh["is_attacker"].astype(str)
    assign = _group_stratified_split(veh["vehicle_key"].to_numpy(), strata.to_numpy())
    man["split"] = man["vehicle_key"].map(assign).fillna("train")

    man = man[["run_id", "attack_percentage", "claimed_node_id", "real_vehicle",
               "vehicle_key", "is_sybil", "attack_type", "split"]]
    man.to_parquet(SPLIT_MAP_PATH, index=False)
    if verbose:
        print(f"\nsplit_map -> {SPLIT_MAP_PATH}  ({len(man):,} kept ids)")
        print("split counts:", man["split"].value_counts().to_dict())
        print("no-leak check (vehicle in >1 split):",
              int((man.groupby('vehicle_key')['split'].nunique() > 1).sum()))
    return man


def load_manifest(force=False, nrows=None):
    """Load the shared split_map, building it once if absent."""
    if SPLIT_MAP_PATH.exists() and not force:
        return pd.read_parquet(SPLIT_MAP_PATH)
    print("Building shared identity manifest (one-time, scans communication_logs)...")
    return build_manifest(nrows=nrows)


# ════════════════════════════════════════════════════════════════════════════
# Consume (helpers for the notebooks)
# ════════════════════════════════════════════════════════════════════════════
def _keys(df, run_col, claimed_col):
    return list(zip(df[run_col].astype(str), df[claimed_col].astype(int)))


def keep_mask(df, man, run_col="run_id", claimed_col="claimed_node_id"):
    """Boolean mask: keep only rows whose (run_id, claimed_node_id) is in the
    shared subsample. Use to filter EVERY model to the identical identity set."""
    kept = set(zip(man["run_id"].astype(str), man["claimed_node_id"].astype(int)))
    return np.fromiter((k in kept for k in _keys(df, run_col, claimed_col)),
                       dtype=bool, count=len(df))


def attach_split(df, man, run_col="run_id", claimed_col="claimed_node_id"):
    """Return df with a 'split' column from the shared map (rows not in the map
    are dropped — they are outside the subsample)."""
    key = man[["run_id", "claimed_node_id", "split"]].copy()
    key["claimed_node_id"] = key["claimed_node_id"].astype(int)
    out = df.copy()
    out[claimed_col] = out[claimed_col].astype(int)
    out = out.merge(key, left_on=[run_col, claimed_col],
                    right_on=["run_id", "claimed_node_id"], how="inner",
                    suffixes=("", "_map"))
    return out


def split_of(run_ids, claimed_ids, man):
    """Vectorised (run_id, claimed_id) -> split lookup ('train' default)."""
    d = {(str(r), int(c)): s for r, c, s in
         zip(man["run_id"], man["claimed_node_id"], man["split"])}
    return np.array([d.get((str(r), int(c)), "train")
                     for r, c in zip(run_ids, claimed_ids)], dtype=object)


def snap_grid(seconds, grid=EXPORT_GRID_S):
    """Snap window_start_seconds to the shared export grid."""
    return (np.floor(np.asarray(seconds, dtype=float) / grid) * grid).astype("float32")


# ════════════════════════════════════════════════════════════════════════════
# Memory-safe log reading (HPC: comm_log is ~12 GB / 63 M rows per run)
# ════════════════════════════════════════════════════════════════════════════
READ_CHUNK = 3_000_000   # rows per chunk (~a few hundred MB at these widths)


def kept_ids_for_run(run_id, man=None):
    man = man if man is not None else load_manifest()
    return set(man.loc[man["run_id"] == str(run_id), "claimed_node_id"].astype(int))


def read_run_log_filtered(path, usecols, claimed_col, run_id, man=None,
                          chunksize=READ_CHUNK, extra_filter=None, verbose=True):
    """Stream a multi-GB run log in chunks, keeping ONLY rows whose claimed id is in
    the shared subsample for this run. Peak RAM ≈ one chunk + the kept subset, so the
    full 12 GB file is NEVER materialised (this is the fix for the previous HPC stall).
    `extra_filter(chunk)->mask` optionally drops more rows per chunk before accumulating."""
    kept = kept_ids_for_run(run_id, man)
    parts, total, keptn = [], 0, 0
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=chunksize):
        total += len(chunk)
        m = chunk[claimed_col].astype("int64").isin(kept)
        chunk = chunk[m]
        if extra_filter is not None and len(chunk):
            chunk = chunk[extra_filter(chunk)]
        for c in chunk.select_dtypes("int64").columns:
            chunk[c] = pd.to_numeric(chunk[c], downcast="integer")
        for c in chunk.select_dtypes("float64").columns:
            chunk[c] = pd.to_numeric(chunk[c], downcast="float")
        parts.append(chunk); keptn += len(chunk)
    df = (pd.concat(parts, ignore_index=True) if parts
          else pd.DataFrame(columns=list(usecols)))
    if verbose:
        print(f"    [safe-read] {os.path.basename(path)}: scanned {total:,} rows, "
              f"kept {keptn:,} ({100*keptn/max(total,1):.1f}%)")
    return df


def count_kept_rows(path, usecols, claimed_col, run_id, man=None, chunksize=READ_CHUNK):
    """Count kept rows without materialising them (for the pre-flight estimator)."""
    kept = kept_ids_for_run(run_id, man)
    total = keptn = 0
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=chunksize):
        total += len(chunk)
        keptn += int(chunk[claimed_col].astype("int64").isin(kept).sum())
    return total, keptn


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--nrows", type=int, default=None, help="smoke build on N rows/run")
    a = ap.parse_args()
    build_manifest(nrows=a.nrows) if a.force or not SPLIT_MAP_PATH.exists() else \
        print("exists:", SPLIT_MAP_PATH, "(use --force to rebuild)")
