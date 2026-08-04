#!/usr/bin/env python3
"""
q39_beacon_window_check.py — Q39 sliding-window sanity check on the beacon log.

For every (observer, claimed_identity) pair in communication_log.csv, take
sliding windows of W consecutive beacons and verify:
  1. timestamps are strictly monotonically increasing (no time reversal)
  2. inter-arrival times sit near the beacon interval (default 0.1 s +/- 20 ms)
  3. no window straddles a gap > GAP_MAX seconds (a cross-episode window: the
     claimed identity went out of the observer's range and came back)

Beacon rows are message_type == 1 (col 8). The observer is the receiving node,
keyed as (receiver_role, receiver_id) because vehicle and RSU ids share a
namespace. The claimed identity is claimed_node_id (col 6) — the id asserted in
the beacon, which is what a detector windows on (real_node_id is ground truth
and is only used here to label a pair as sybil/genuine).

Rows are consumed in file order; timestamps are NOT sorted first, so a reported
reversal is a real ordering defect in the log as written, not an artefact.

Usage:
  python3 q39_beacon_window_check.py <run_dir> [<run_dir> ...]
  python3 q39_beacon_window_check.py --csv out.csv datasets/type2_mode4_sweep_*/pct*_s1
Options:
  -W N          window size            [10]
  --interval S  expected inter-arrival [0.1]
  --jitter S    tolerance              [0.02]
  --gap S       cross-episode gap      [5.0]
  --csv PATH    also write the per-run summary as CSV
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

COL_TIME = 0
COL_ROLE = 2
COL_RECV = 3
COL_REAL = 4
COL_CLAIMED = 5
COL_MSGTYPE = 7


def check_run(run_dir, W, interval, jitter, gap_max):
    path = os.path.join(run_dir, "communication_log.csv")
    if not os.path.isfile(path):
        return None

    series = defaultdict(list)      # (role, recv, claimed) -> [t, ...]
    is_sybil = {}                   # same key -> claimed != real seen at least once
    beacon_rows = 0

    with open(path, "r", newline="") as fh:
        rd = csv.reader(fh)
        next(rd, None)
        for row in rd:
            if len(row) <= COL_MSGTYPE or row[COL_MSGTYPE] != "1":
                continue
            try:
                t = float(row[COL_TIME])
            except ValueError:
                continue
            key = (row[COL_ROLE], row[COL_RECV], row[COL_CLAIMED])
            series[key].append(t)
            beacon_rows += 1
            if row[COL_CLAIMED] != row[COL_REAL]:
                is_sybil[key] = True

    st = {
        "run": os.path.basename(run_dir.rstrip("/")),
        "beacon_rows": beacon_rows,
        "pairs": len(series),
        "pairs_ge_W": 0,
        "windows": 0,
        "win_reversal": 0,
        "win_gap": 0,
        "win_clean": 0,
        "gaps_total": 0,
        "reversals_total": 0,
        "ia_total": 0,
        "ia_in_band": 0,
        "ia_min": None,
        "ia_max": None,
        "ia_median": None,
        "dup_zero_ia": 0,
        "sybil_pairs": len(is_sybil),
        "worst_gap": 0.0,
        "worst_reversal": 0.0,
    }

    all_ia = []
    for key, ts in series.items():
        n = len(ts)
        ia = [ts[i + 1] - ts[i] for i in range(n - 1)]
        for d in ia:
            st["ia_total"] += 1
            if d < 0:
                st["reversals_total"] += 1
                st["worst_reversal"] = min(st["worst_reversal"], d)
            elif d == 0.0:
                st["dup_zero_ia"] += 1
            if d > gap_max:
                st["gaps_total"] += 1
                st["worst_gap"] = max(st["worst_gap"], d)
            if abs(d - interval) <= jitter:
                st["ia_in_band"] += 1
        all_ia.extend(ia)

        if n < W:
            continue
        st["pairs_ge_W"] += 1
        # sliding windows of W beacons = W-1 inter-arrivals each
        for s in range(0, n - W + 1):
            st["windows"] += 1
            w = ia[s:s + W - 1]
            has_rev = any(d < 0 for d in w)
            has_gap = any(d > gap_max for d in w)
            if has_rev:
                st["win_reversal"] += 1
            if has_gap:
                st["win_gap"] += 1
            if not has_rev and not has_gap:
                st["win_clean"] += 1

    if all_ia:
        all_ia.sort()
        st["ia_min"] = all_ia[0]
        st["ia_max"] = all_ia[-1]
        st["ia_median"] = all_ia[len(all_ia) // 2]
    return st


def fmt(v, nd=4):
    return "-" if v is None else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("-W", type=int, default=10)
    ap.add_argument("--interval", type=float, default=0.1)
    ap.add_argument("--jitter", type=float, default=0.02)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--csv", default=None)
    a = ap.parse_args()

    print(f"Q39 window check  W={a.W}  interval={a.interval}s +/-{a.jitter}s  "
          f"cross-episode gap>{a.gap}s")
    print("=" * 118)
    hdr = ("run", "beacons", "pairs", ">=W", "windows", "rev_win", "gap_win",
           "clean%", "ia_med", "ia_max", "in_band%")
    print("%-16s %10s %7s %7s %10s %8s %8s %8s %8s %9s %9s" % hdr)

    rows = []
    for run in a.runs:
        st = check_run(run, a.W, a.interval, a.jitter, a.gap)
        if st is None:
            print(f"{os.path.basename(run.rstrip('/')):<16}  (no communication_log.csv — skipped)")
            continue
        rows.append(st)
        clean_pct = 100.0 * st["win_clean"] / st["windows"] if st["windows"] else 0.0
        band_pct = 100.0 * st["ia_in_band"] / st["ia_total"] if st["ia_total"] else 0.0
        print("%-16s %10d %7d %7d %10d %8d %8d %7.2f%% %8s %9s %8.2f%%" % (
            st["run"], st["beacon_rows"], st["pairs"], st["pairs_ge_W"],
            st["windows"], st["win_reversal"], st["win_gap"], clean_pct,
            fmt(st["ia_median"]), fmt(st["ia_max"], 2), band_pct))

    print("=" * 118)
    for st in rows:
        print(f"  {st['run']}: reversals={st['reversals_total']} "
              f"(worst {fmt(st['worst_reversal'])}s)  gaps>{a.gap}s={st['gaps_total']} "
              f"(worst {fmt(st['worst_gap'], 2)}s)  zero-dt dups={st['dup_zero_ia']}  "
              f"sybil-claim pairs={st['sybil_pairs']}")

    if a.csv and rows:
        with open(a.csv, "w", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)
        print(f"\nwrote {a.csv}")

    # exit 1 if any window is contaminated — the Q39 failure condition
    bad = sum(r["win_reversal"] + r["win_gap"] for r in rows)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
