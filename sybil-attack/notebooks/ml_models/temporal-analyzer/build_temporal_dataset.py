#!/usr/bin/env python3
"""
build_temporal_dataset.py — TEMPORAL analyzer dataset (model 1).

Reads each scenario's communication_log.csv from a solution dataset run and
produces ONE row per (scenario, claimed_id) of timing/lifetime/churn features.
This model targets type3 (pseudonym churn / single-beacon) and the simultaneity
side of type2 — signals that live purely in WHEN beacons arrive.

Output: solution_data/temporal_dataset.csv

Usage:
  python3 build_temporal_dataset.py [--run-dir sybil-attack/datasets/solution_ds_XXXX]
"""
import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_ns3_root(start):
    d = start
    while d != "/" and not os.path.isfile(os.path.join(d, "waf")):
        d = os.path.dirname(d)
    return d


NS3_ROOT = _find_ns3_root(HERE)
OUT_DIR = HERE   # write temporal_dataset.csv next to this script


def newest_solution_run():
    runs = sorted(glob.glob(os.path.join(NS3_ROOT, "sybil-attack", "datasets",
                                          "solution_ds_*")))
    return runs[-1] if runs else None


def temporal_features_for_scenario(csv_path, scenario):
    raw = pd.read_csv(csv_path)
    bsm = raw[(raw["flow"] == "v2v_beacon") & (raw["message_type"] == 1)].copy()
    if bsm.empty:
        return pd.DataFrame()
    # one row per broadcast event (a beacon is received by many → dedup)
    bsm = bsm.drop_duplicates(subset=["claimed_node_id", "receive_time"])
    bsm["label"] = (bsm["real_node_id"] != bsm["claimed_node_id"]).astype(int)

    # run-level churn: how many DISTINCT ids are first seen in each 1 s bin
    first_seen = bsm.groupby("claimed_node_id")["receive_time"].min()
    birth_bin = first_seen.astype(int)
    ids_per_bin = birth_bin.value_counts().to_dict()  # bin -> #new ids that second

    rows = []
    for cid, g in bsm.groupby("claimed_node_id"):
        t = np.sort(g["receive_time"].values.astype(float))
        n = len(t)
        lifetime = float(t[-1] - t[0]) if n > 1 else 0.0
        iat = np.diff(t) if n > 1 else np.array([])
        rows.append({
            "scenario":        scenario,
            "claimed_id":      int(cid),
            "n_broadcasts":    n,
            "single_beacon":   int(n == 1),
            "lifetime_s":      lifetime,
            "iat_mean":        float(iat.mean()) if iat.size else 0.0,
            "iat_std":         float(iat.std())  if iat.size else 0.0,
            "iat_cv":          float(iat.std() / iat.mean()) if iat.size and iat.mean() > 0 else 0.0,
            "beacon_rate":     n / lifetime if lifetime > 0 else 0.0,
            "first_seen_s":    float(t[0]),
            "birth_churn":     int(ids_per_bin.get(int(first_seen[cid]), 1)),
            "label":           int(g["label"].max()),
        })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--out", default=os.path.join(OUT_DIR, "temporal_dataset.csv"))
    args = ap.parse_args()

    run_dir = args.run_dir or newest_solution_run()
    if not run_dir or not os.path.isdir(run_dir):
        raise SystemExit("No solution_ds_* run dir found. Run "
                         "run_solution_dataset.sh first.")
    print(f"[temporal] source: {run_dir}")

    frames = []
    for scenario in sorted(os.listdir(run_dir)):
        log = os.path.join(run_dir, scenario, "communication_log.csv")
        if not os.path.isfile(log):
            continue
        df = temporal_features_for_scenario(log, scenario)
        if not df.empty:
            frames.append(df)
            print(f"  {scenario:14s} {len(df):5d} identities  "
                  f"(sybil={int(df['label'].sum())})")
    if not frames:
        raise SystemExit("No communication_log.csv files found.")
    out = pd.concat(frames, ignore_index=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    out.to_csv(args.out, index=False)
    print(f"\n[temporal] wrote {len(out)} rows -> {args.out}")
    print(f"[temporal] label balance: {out['label'].value_counts().to_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
