#!/usr/bin/env python3
# =============================================================================
# plot_solution_mode2.py
#
# Two sub-commands, used by run_solution_mode2_sweep.sh:
#
#   extract  -- read a single run's metrics_M5_M6_detection_quality.csv,
#               pool TP/FP/FN/TN across all time windows, recompute
#               MCC / FPR / Precision / Recall, and append one row to the
#               aggregate solution_mode_2_results.csv.
#
#   plot     -- read solution_mode_2_results.csv and render four PNGs:
#               MCC, Recall, Precision, FPR  (y) vs attack_percentage (x),
#               one line per attack type.
#
# Standalone usage:
#   python3 plot_solution_mode2.py extract --detection-csv <csv> \
#       --attack-type 1 --attack-percentage 20 --out-csv <results.csv>
#   python3 plot_solution_mode2.py plot --results-csv <results.csv> \
#       --out-dir <dir>
# =============================================================================
import argparse
import csv
import math
import os
import sys


# ---- attack-type labels (mirror SybilAttackType in sybil_types.h) -----------
ATTACK_LABELS = {
    1: "T1 Outsider",
    2: "T2 Insider direct simultaneous",
    3: "T3 Insider direct non-simultaneous",
    4: "T4 Insider indirect (relay)",
    5: "T5 Malicious RSU",
}


def pooled_metrics(tp, fp, fn, tn):
    """Recompute detection metrics from pooled confusion counts."""
    # Matthews Correlation Coefficient
    denom = math.sqrt(
        (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    )
    mcc = ((tp * tn) - (fp * fn)) / denom if denom > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return mcc, fpr, precision, recall


def parse_rssi_summary(path):
    """Read the '#SUMMARY,key=val,...' line written by the RSSI detector
    (rssi_sybil_detection.h::PrintMetrics) at the end of its log CSV.
    Returns (tp, fp, fn, tn) cumulative final confusion counts, or None."""
    summary = None
    with open(path) as fh:
        for line in fh:
            if line.startswith("#SUMMARY"):
                summary = line.strip()
    if summary is None:
        return None
    kv = {}
    for tok in summary.split(",")[1:]:        # skip the leading '#SUMMARY'
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k.strip()] = v.strip()
    return (
        int(float(kv["TP"])), int(float(kv["FP"])),
        int(float(kv["FN"])), int(float(kv["TN"])),
    )


def cmd_extract(args):
    tp = fp = fn = tn = 0
    parsed = None
    try:
        parsed = parse_rssi_summary(args.detection_csv)
    except FileNotFoundError:
        sys.stderr.write(
            f"[extract] WARNING: {args.detection_csv} not found; "
            f"writing zero row for type={args.attack_type} pct={args.attack_percentage}\n"
        )
    if parsed is None:
        sys.stderr.write(
            f"[extract] WARNING: no #SUMMARY line in {args.detection_csv}; "
            f"writing zero row for type={args.attack_type} pct={args.attack_percentage}\n"
        )
    else:
        tp, fp, fn, tn = parsed

    mcc, fpr, precision, recall = pooled_metrics(tp, fp, fn, tn)

    write_header = not os.path.exists(args.out_csv) or os.path.getsize(args.out_csv) == 0
    with open(args.out_csv, "a", newline="") as fh:
        w = csv.writer(fh)
        if write_header:
            w.writerow(
                ["attack_type", "attack_percentage", "TP", "FP", "FN", "TN",
                 "MCC", "FPR", "Precision", "Recall"]
            )
        w.writerow(
            [args.attack_type, args.attack_percentage, tp, fp, fn, tn,
             f"{mcc:.6f}", f"{fpr:.6f}", f"{precision:.6f}", f"{recall:.6f}"]
        )

    sys.stderr.write(
        f"[extract] type={args.attack_type} pct={args.attack_percentage} "
        f"TP={tp} FP={fp} FN={fn} TN={tn} "
        f"MCC={mcc:.4f} FPR={fpr:.4f} P={precision:.4f} R={recall:.4f}\n"
    )


def cmd_plot(args):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # data[attack_type][pct] = {metric: value}
    data = {}
    with open(args.results_csv, newline="") as fh:
        for row in csv.DictReader(fh):
            t = int(row["attack_type"])
            p = float(row["attack_percentage"])
            data.setdefault(t, {})[p] = {
                "MCC": float(row["MCC"]),
                "Recall": float(row["Recall"]),
                "Precision": float(row["Precision"]),
                "FPR": float(row["FPR"]),
            }

    if not data:
        sys.stderr.write(f"[plot] no rows in {args.results_csv}\n")
        return

    metrics = ["MCC", "Recall", "Precision", "FPR"]
    os.makedirs(args.out_dir, exist_ok=True)

    for metric in metrics:
        plt.figure(figsize=(8, 5.5))
        for t in sorted(data):
            pcts = sorted(data[t])
            ys = [data[t][p][metric] for p in pcts]
            plt.plot(
                pcts, ys, marker="o", linewidth=1.8,
                label=ATTACK_LABELS.get(t, f"Type {t}"),
            )
        plt.title(f"{metric} vs Attack Percentage (solution_mode=2, mobility_mode=5)")
        plt.xlabel("Attack percentage (%)")
        plt.ylabel(metric)
        plt.grid(True, linestyle="--", alpha=0.4)
        if metric in ("MCC", "Recall", "Precision"):
            plt.ylim(-0.05, 1.05)
        plt.legend(fontsize=8, loc="best")
        plt.tight_layout()
        out_png = os.path.join(args.out_dir, f"solution_mode2_{metric.lower()}.png")
        plt.savefig(out_png, dpi=150)
        plt.close()
        sys.stderr.write(f"[plot] wrote {out_png}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("extract", help="pool one run's metrics and append a row")
    pe.add_argument("--detection-csv", required=True)
    pe.add_argument("--attack-type", required=True, type=int)
    pe.add_argument("--attack-percentage", required=True, type=float)
    pe.add_argument("--out-csv", required=True)
    pe.set_defaults(func=cmd_extract)

    pp = sub.add_parser("plot", help="render the four metric graphs")
    pp.add_argument("--results-csv", required=True)
    pp.add_argument("--out-dir", required=True)
    pp.set_defaults(func=cmd_plot)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
