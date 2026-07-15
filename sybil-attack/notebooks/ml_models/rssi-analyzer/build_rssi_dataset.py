#!/usr/bin/env python3
"""
build_rssi_dataset.py — RSSI analyzer dataset (model 2).

The simulator's rssi_verification_log.csv already IS the RSSI dataset (one row
per observation: an observer hearing a claimed id). This script only does light
hygiene across the solution dataset's scenarios:
  * concatenate every scenario's rssi_verification_log.csv,
  * add label = (observed_real_id != observed_claimed_id),
  * tag each row with its scenario,
  * DROP verification_state + suspicion_flags (those are the OLD RSSI detector's
    verdict -> training on them is leakage).

Features kept (signal vs claimed-position): rssi_dbm, rssi_estimated_distance_m,
claimed_distance_m, mismatch_m, threshold_m.

Output: rssi_dataset.csv (next to this script)

Usage:
  python3 build_rssi_dataset.py [--run-dir sybil-attack/datasets/solution_ds_XXXX]
"""
import argparse
import glob
import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_ns3_root(start):
    d = start
    while d != "/" and not os.path.isfile(os.path.join(d, "waf")):
        d = os.path.dirname(d)
    return d


NS3_ROOT = _find_ns3_root(HERE)
LEAKAGE_COLS = ["verification_state", "rssi_verification_state", "suspicion_flags"]
FEATURE_COLS = ["rssi_dbm", "rssi_estimated_distance_m", "claimed_distance_m",
                "mismatch_m", "threshold_m"]


def newest_solution_run():
    runs = sorted(glob.glob(os.path.join(NS3_ROOT, "sybil-attack", "datasets",
                                          "solution_ds_*")))
    return runs[-1] if runs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--out", default=os.path.join(HERE, "rssi_dataset.csv"))
    args = ap.parse_args()

    run_dir = args.run_dir or newest_solution_run()
    if not run_dir or not os.path.isdir(run_dir):
        raise SystemExit("No solution_ds_* run dir found. Run "
                         "run_solution_dataset.sh first.")
    print(f"[rssi] source: {run_dir}")

    frames = []
    for scenario in sorted(os.listdir(run_dir)):
        log = os.path.join(run_dir, scenario, "rssi_verification_log.csv")
        if not os.path.isfile(log):
            continue
        df = pd.read_csv(log)
        if df.empty:
            continue
        df["label"] = (df["observed_real_id"] != df["observed_claimed_id"]).astype(int)
        df["scenario"] = scenario
        df = df.drop(columns=[c for c in LEAKAGE_COLS if c in df.columns])
        frames.append(df)
        print(f"  {scenario:14s} {len(df):8d} observations  "
              f"(sybil={int(df['label'].sum())})")
    if not frames:
        raise SystemExit("No rssi_verification_log.csv files found.")

    out = pd.concat(frames, ignore_index=True)
    # reorder: keys, features, label
    keep = ["scenario", "time", "observer_vehicle_id", "observed_claimed_id",
            "observed_real_id"] + FEATURE_COLS + ["label"]
    out = out[[c for c in keep if c in out.columns]]
    out.to_csv(args.out, index=False)
    print(f"\n[rssi] wrote {len(out)} rows -> {args.out}")
    print(f"[rssi] features: {[c for c in FEATURE_COLS if c in out.columns]}")
    print(f"[rssi] label balance: {out['label'].value_counts().to_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
