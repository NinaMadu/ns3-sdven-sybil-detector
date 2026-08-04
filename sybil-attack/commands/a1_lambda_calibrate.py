#!/usr/bin/env python3
"""Calibrate the A1 mode-selector thresholds from measured Lambda(t) traces.

Reads mode_selector_log.csv from the a1lambda_* characterization runs and

  1. reports the empirical Lambda distribution per condition (the candidate
     range for the parameters table comes from these percentiles);
  2. replays the Eq 3.11 selector -- WITH hysteresis and dwell -- offline over a
     grid of (Lambda_hi, Lambda_lo, T_d), reporting switch count and engaged
     fraction for each cell.

The replay is exact: Lambda(t) is logged every selector tick independently of
the mode decision, and the selector is a pure function of the Lambda trace plus
the three parameters, so sweeping thresholds needs NO further simulation. The
one thing it cannot capture is feedback -- being in Full changes which
suspicion flags fire, hence Lambda itself. That is why the engage side is
calibrated on a trace measured while Lightweight and the disengage side on a
trace measured while Full, rather than both from one run.
"""
import csv
import glob
import os
import sys

DATASETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datasets")


def load(path):
    ts, lam = [], []
    with open(path) as fh:
        for row in csv.DictReader(fh):
            ts.append(float(row["time_s"]))
            lam.append(float(row["lambda"]))
    return ts, lam


def pct(xs, p):
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def replay(ts, lam, hi, lo, dwell, start_full=False):
    """Exact offline replay of EvaluateModeSelector (resources always OK)."""
    engaged = start_full
    last_switch = -1e9
    switches = 0
    eng_time = 0.0
    prev_t = ts[0] if ts else 0.0
    for t, L in zip(ts, lam):
        if engaged:
            eng_time += t - prev_t
        prev_t = t
        want = engaged
        if not engaged:
            if L >= hi:
                want = True
        else:
            if L < lo:
                want = False
        if want != engaged and (t - last_switch) < dwell:
            want = engaged                      # dwell blocks the transition
        if want != engaged:
            last_switch = t
            switches += 1
            engaged = want
    span = (ts[-1] - ts[0]) if len(ts) > 1 else 1.0
    return switches, eng_time / span if span else 0.0


def main():
    runs = sorted(glob.glob(os.path.join(DATASETS, "a1lambda_*", "mode_selector_log.csv")))
    if not runs:
        sys.exit("no a1lambda_* selector logs found")

    traces = {}
    print("=" * 78)
    print("EMPIRICAL LAMBDA DISTRIBUTION  (windowed, W=10s, per 1s selector tick)")
    print("=" * 78)
    print(f"{'condition':<10}{'n':>4}{'min':>8}{'p25':>8}{'p50':>8}{'p75':>8}{'p90':>8}{'max':>8}"
          f"{'  frac>0':>9}")
    for p in runs:
        tag = os.path.basename(os.path.dirname(p)).replace("a1lambda_", "")
        ts, lam = load(p)
        traces[tag] = (ts, lam)
        nz = sum(1 for x in lam if x > 0) / float(len(lam)) if lam else 0.0
        print(f"{tag:<10}{len(lam):>4}{min(lam):>8.3f}{pct(lam,25):>8.3f}{pct(lam,50):>8.3f}"
              f"{pct(lam,75):>8.3f}{pct(lam,90):>8.3f}{max(lam):>8.3f}{nz:>9.2f}")

    print()
    print("=" * 78)
    print("THRESHOLD REPLAY   (switches / fraction of time in FULL)")
    print("  target: switches >= 2 AND 0 < engaged_frac < 1  -> genuine dual-mode")
    print("=" * 78)
    his = [0.10, 0.15, 0.20, 0.30, 0.40, 0.50]
    los = [0.02, 0.05, 0.10, 0.15, 0.20]
    for tag in sorted(traces):
        ts, lam = traces[tag]
        start_full = tag.startswith("hi")
        print(f"\n--- {tag}  (start_full={start_full}, dwell=5s) ---")
        print("          " + "".join(f"lo={l:<9.2f}" for l in los))
        for hi in his:
            cells = []
            for lo in los:
                if lo >= hi:
                    cells.append("     --    ")
                    continue
                sw, ef = replay(ts, lam, hi, lo, 5.0, start_full)
                cells.append(f"  {sw:>2d}/{ef:>4.2f}   ")
            print(f"hi={hi:<6.2f}" + "".join(cells))

    print()
    print("=" * 78)
    print("DWELL SENSITIVITY  (at the selected hi/lo, per condition)")
    print("=" * 78)
    for tag in sorted(traces):
        ts, lam = traces[tag]
        start_full = tag.startswith("hi")
        row = []
        for d in (0.0, 2.0, 5.0, 10.0, 20.0):
            sw, ef = replay(ts, lam, 0.20, 0.05, d, start_full)
            row.append(f"T_d={d:<5.0f}{sw:>3d}/{ef:.2f}   ")
        print(f"{tag:<10}" + "".join(row))


if __name__ == "__main__":
    main()
