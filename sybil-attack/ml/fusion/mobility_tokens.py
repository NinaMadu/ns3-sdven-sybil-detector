"""
Mobility tokens for the Eq 3.31 context vector — {v_rel, rho_c, dt_sync}.

These are the paper's mobility measures that let the LLM tier explain away benign
signal variation ("a fast vehicle with shifting signal can be perfectly
legitimate") and, conversely, flag motion that is inconsistent with a claimed
identity. They are net-new (the 3 vehicle-tier detectors don't emit them) and
join into cᵢ as an optional, nullable source.

Per (run_id, claimed_node_id, 2s window) — the SAME run-scoped, grid-snapped key
the detector parquets use — computed from communication_log.csv ALONE (one
streamed multi-GB log per run, memory-safe via identity_manifest.read_run_log_filtered):

  v_rel   relative velocity magnitude = median claimed BSM speed in the window
          (speed w.r.t. the static RSU infrastructure). High v_rel is the honest
          reason RSSI/handoff vary → an FP-suppression cue.
  rho_c   topology churn = Jaccard distance between the set of OBUs that received
          this identity's beacons in this window vs its previous window
          (1 = neighbourhood fully turned over, 0 = unchanged). NaN on an
          identity's first window (no prior neighbourhood to compare).
  dt_sync handoff-sync gap = largest inter-beacon receive-time gap within the
          window (s). A regularly beaconing, cleanly handed-off vehicle has a
          small gap; a Sybil that pops in and out has an irregular, larger one.
          NaN for single-beacon windows (no gap measurable).

Output: notebooks/outputs/mobility_tokens.parquet  (attack_percentage + split
attached from the shared manifest so it inner-keys onto the temporal spine).

Run in ml/.venv (pandas/pyarrow/numpy).
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from identity_manifest import (  # noqa: E402
    ARTIFACTS_DIR, RUN_DIRS, load_manifest, read_run_log_filtered, snap_grid,
)

OUT_PATH = os.path.join(str(ARTIFACTS_DIR), "mobility_tokens.parquet")

# only the columns we need — keeps the streamed kept-subset small
_COMM_COLS = ["receive_time", "claimed_node_id", "bsm_speed",
              "observing_rsu_id", "observer_obu_id"]


def _run_id(run_dir):
    import json
    meta = json.load(open(os.path.join(run_dir, "run_meta.json")))
    return str(meta.get("run_id", os.path.basename(run_dir)))


def _churn_per_identity(sets_df):
    """Jaccard distance between an identity's consecutive-window observer sets.
    sets_df: columns [claimed_node_id, window_start_seconds, obs_set], one row per
    (id, window). Returns a rho_c Series aligned to sets_df's (sorted) order."""
    sets_df = sets_df.sort_values(["claimed_node_id", "window_start_seconds"])
    rho = np.full(len(sets_df), np.nan)
    ids = sets_df["claimed_node_id"].to_numpy()
    obs = sets_df["obs_set"].to_numpy()
    prev_set, prev_id = None, None
    for i in range(len(sets_df)):
        if prev_id == ids[i] and prev_set is not None:
            cur = obs[i]
            union = len(cur | prev_set)
            rho[i] = 0.0 if union == 0 else 1.0 - len(cur & prev_set) / union
        prev_set, prev_id = obs[i], ids[i]
    sets_df = sets_df.copy()
    sets_df["rho_c"] = rho
    return sets_df[["claimed_node_id", "window_start_seconds", "rho_c"]]


def tokens_from_df(df, run_id, verbose=True):
    """Core mobility-token computation from a preloaded communication-log df with columns
    [receive_time, claimed_node_id, bsm_speed, observer_obu_id]. Shared by the offline batch
    build (build_run) and the live daemon (ml/serve/mobility_live) so both emit identical
    {v_rel, rho_c, dt_sync} tokens on the same 2 s grid. Returns None if no usable rows."""
    df = df.dropna(subset=["receive_time", "claimed_node_id"])
    if df.empty:
        return None
    df = df.copy()
    df["claimed_node_id"] = df["claimed_node_id"].astype(int)
    df["window_start_seconds"] = snap_grid(df["receive_time"].to_numpy())

    g = df.groupby(["claimed_node_id", "window_start_seconds"], sort=False)
    agg = g.agg(v_rel=("bsm_speed", "median"),
                n_beacons=("receive_time", "size")).reset_index()

    # dt_sync — largest inter-beacon gap inside each window
    s = df.sort_values(["claimed_node_id", "window_start_seconds", "receive_time"])
    s["gap"] = s.groupby(["claimed_node_id", "window_start_seconds"])["receive_time"].diff()
    dt = (s.groupby(["claimed_node_id", "window_start_seconds"])["gap"].max()
            .reset_index().rename(columns={"gap": "dt_sync"}))
    agg = agg.merge(dt, on=["claimed_node_id", "window_start_seconds"], how="left")

    # rho_c — observer-set churn across an identity's consecutive windows
    sets_df = (g["observer_obu_id"].apply(lambda x: frozenset(x.dropna().astype(int)))
                 .reset_index().rename(columns={"observer_obu_id": "obs_set"}))
    rho = _churn_per_identity(sets_df)
    agg = agg.merge(rho, on=["claimed_node_id", "window_start_seconds"], how="left")

    agg["run_id"] = run_id
    if verbose:
        print(f"  {run_id}: {len(agg):,} (id,window) rows | "
              f"v_rel~{agg['v_rel'].median():.1f} | rho_c cov "
              f"{agg['rho_c'].notna().mean()*100:.0f}% | dt_sync cov "
              f"{agg['dt_sync'].notna().mean()*100:.0f}%")
    return agg[["run_id", "claimed_node_id", "window_start_seconds",
                "v_rel", "rho_c", "dt_sync"]]


def build_run(run_dir, man):
    run_id = _run_id(run_dir)
    comm = os.path.join(run_dir, "communication_log.csv")
    df = read_run_log_filtered(comm, _COMM_COLS, "claimed_node_id", run_id, man=man)
    if df.empty:
        print(f"  {run_id}: no kept rows")
        return None
    return tokens_from_df(df, run_id)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT_PATH)
    args = ap.parse_args()

    man = load_manifest()
    print(f"Building mobility tokens for {len(RUN_DIRS)} runs -> {args.out}")
    parts = [p for rd in RUN_DIRS if (p := build_run(rd, man)) is not None]
    if not parts:
        raise SystemExit("no mobility rows produced")
    mob = pd.concat(parts, ignore_index=True)

    # attach attack_percentage + split from the shared manifest so the key matches
    # the detector parquets exactly (inner-keeps only kept identities → already are)
    key = man[["run_id", "claimed_node_id", "attack_percentage", "split"]].copy()
    key["claimed_node_id"] = key["claimed_node_id"].astype(int)
    mob = mob.merge(key, on=["run_id", "claimed_node_id"], how="inner")
    mob["window_start_seconds"] = mob["window_start_seconds"].astype("float32")

    mob = mob[["run_id", "attack_percentage", "claimed_node_id",
               "window_start_seconds", "split", "v_rel", "rho_c", "dt_sync"]]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    mob.to_parquet(args.out, index=False)
    print(f"\nwrote {mob.shape} -> {args.out}")
    print(f"  runs: {sorted(mob['run_id'].unique())}")
    print(f"  split: {mob['split'].value_counts().to_dict()}")
    print(mob[["v_rel", "rho_c", "dt_sync"]].describe().round(3).to_string())


if __name__ == "__main__":
    main()
