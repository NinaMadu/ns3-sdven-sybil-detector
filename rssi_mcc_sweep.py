#!/usr/bin/env python3
"""
rssi_mcc_sweep.py
Sweeps sybil_attack_type in {1,2,3,4,5} and sybil_attack_percentage in {0,20,40,60,80,100}
with solution_mode=2 (RSSI paper baseline) and plots MCC vs attack percentage.

Run from ns-3.35/:
    python3 rssi_mcc_sweep.py
"""

import subprocess
import re
import csv
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── Sweep configuration ────────────────────────────────────────────────────────
ATTACK_TYPES = [1, 2, 3, 4, 5]
PERCENTAGES  = [0, 20, 40, 60, 80, 100]
SIM_TIME     = 120
MOBILITY_MODE = 2

WAF_DIR    = os.path.expanduser("~/FYP/ns-allinone-3.35/ns-3.35")
OUTPUT_DIR = os.path.join(WAF_DIR, "sybil-attack/outputs")
CSV_FILE   = os.path.join(OUTPUT_DIR, "rssi_mcc_sweep.csv")
PLOT_FILE  = os.path.join(OUTPUT_DIR, "rssi_mcc_sweep.png")

# ── Helpers ────────────────────────────────────────────────────────────────────

def run_simulation(attack_type: int, percentage: int) -> str:
    args = (
        f"Sybil-Developing-Improved "
        f"--mobility_mode={MOBILITY_MODE} "
        f"--routing_test=false "
        f"--simTime={SIM_TIME} "
        f"--solution_mode=2 "
        f"--sybil_attack_type={attack_type} "
        f"--sybil_attack_enabled=true "
        f"--sybil_attack_percentage={percentage}"
    )
    result = subprocess.run(
        ["./waf", "--run", args],
        capture_output=True, text=True,
        cwd=WAF_DIR
    )
    return result.stdout + result.stderr


def parse_rssi_mcc(output: str) -> float | None:
    """
    Extract MCC from RssiSybilDetector::PrintMetrics() block.
    Header: 'RSSI SYBIL DETECTION — EVALUATION METRICS'
    MCC line: 'MCC       (Matthews Corr. Coef) : 0.0000'
    """
    lines = output.splitlines()
    in_rssi_block = False
    for line in lines:
        if re.search(r'RSSI SYBIL DETECTION|rssi_sybil_detection|RSSI_paper_baseline', line):
            in_rssi_block = True
        if in_rssi_block:
            # Matches 'MCC       (Matthews Corr. Coef) : 0.0000'
            m = re.search(r'MCC.*?:\s*([0-9.naAN]+)', line)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    return float('nan')
    return None


def parse_tp_fp_tn_fn(output: str):
    """
    Parse TP/FP/FN/TN from RssiSybilDetector::PrintMetrics() block.
    Output format: 'TP=0  FP=0  TN=106  FN=122'  (order: TP FP TN FN)
    Returns (TP, FP, FN, TN).
    """
    lines = output.splitlines()
    in_rssi_block = False
    for line in lines:
        if re.search(r'RSSI SYBIL DETECTION|rssi_sybil_detection|RSSI_paper_baseline', line):
            in_rssi_block = True
        if in_rssi_block:
            # Output order is TP FP TN FN
            m = re.search(r'TP=(\d+)\s+FP=(\d+)\s+TN=(\d+)\s+FN=(\d+)', line)
            if m:
                tp, fp, tn, fn = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
                return tp, fp, fn, tn  # caller expects (TP, FP, FN, TN)
    return None, None, None, None

# ── Main sweep ─────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total = len(ATTACK_TYPES) * len(PERCENTAGES)
    done  = 0
    results = []

    for attack_type in ATTACK_TYPES:
        for pct in PERCENTAGES:
            done += 1
            print(f"\n[{done}/{total}] attack_type={attack_type}  percentage={pct}%  ...",
                  flush=True)
            output = run_simulation(attack_type, pct)
            mcc = parse_rssi_mcc(output)
            tp, fp, fn, tn = parse_tp_fp_tn_fn(output)

            if mcc is None:
                debug_file = os.path.join(OUTPUT_DIR,
                    f"debug_type{attack_type}_pct{pct}.txt")
                with open(debug_file, 'w', errors='replace') as dbf:
                    dbf.write(output)
                print(f"  WARNING: MCC not found in output — storing NaN")
                print(f"  (full output saved to {debug_file})")
                mcc = float('nan')
            else:
                print(f"  MCC={mcc:.4f}  TP={tp} FP={fp} FN={fn} TN={tn}")

            results.append({
                'attack_type': attack_type,
                'percentage':  pct,
                'mcc':         round(mcc, 6) if mcc == mcc else 'nan',
                'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
            })

    # ── CSV ────────────────────────────────────────────────────────────────────
    fields = ['attack_type', 'percentage', 'mcc', 'TP', 'FP', 'FN', 'TN']
    with open(CSV_FILE, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(results)
    print(f"\nCSV  →  {CSV_FILE}")

    # ── Plot ───────────────────────────────────────────────────────────────────
    markers = {1: 'o', 2: 's', 3: '^', 4: 'd', 5: 'v'}
    colors  = {1: 'tab:blue', 2: 'tab:orange', 3: 'tab:green', 4: 'tab:red', 5: 'tab:purple'}
    labels  = {1: 'Attack Type 1', 2: 'Attack Type 2', 3: 'Attack Type 3', 4: 'Attack Type 4', 5: 'Attack Type 5'}

    fig, ax = plt.subplots(figsize=(8, 5))

    for at in ATTACK_TYPES:
        subset = [r for r in results if r['attack_type'] == at]
        x = [r['percentage'] for r in subset]
        y = [r['mcc'] if r['mcc'] != 'nan' else float('nan') for r in subset]
        ax.plot(x, y,
                marker=markers[at], color=colors[at],
                label=labels[at], linewidth=2, markersize=7)

    ax.set_xlabel('Sybil Attack Percentage (%)', fontsize=12)
    ax.set_ylabel('MCC', fontsize=12)
    ax.set_title('RSSI Paper Baseline — MCC vs Sybil Attack Percentage', fontsize=13)
    ax.set_xticks(PERCENTAGES)
    ax.set_ylim(-0.15, 1.05)
    ax.axhline(0, color='grey', linewidth=0.8, linestyle='--')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOT_FILE, dpi=150)
    print(f"Plot →  {PLOT_FILE}")
    plt.close()


if __name__ == '__main__':
    main()
