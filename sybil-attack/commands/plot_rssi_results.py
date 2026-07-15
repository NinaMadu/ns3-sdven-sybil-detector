#!/usr/bin/env python3
"""
plot_rssi_results.py — Draw MCC and FPR vs attack percentage graphs
from the rssi_percentage_sweep.csv output.

Usage:
    python3 sybil-attack/commands/plot_rssi_results.py
"""

import os
import csv
import matplotlib
matplotlib.use("Agg")          # no display needed — saves PNG files
import matplotlib.pyplot as plt

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIM_DIR  = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
CSV_PATH = os.path.join(SIM_DIR, "sybil-attack", "outputs", "rssi_percentage_sweep.csv")
OUT_DIR  = os.path.join(SIM_DIR, "sybil-attack", "outputs")

ATTACK_LABELS = {

    "1": "Type 1 — Outsider Sybil",
    "2": "Type 2 — Direct Simultaneous",
    "3": "Type 3 — Direct Non-Simultaneous",
    "4": "Type 4 — Indirect Relay",
    "5": "Type 5 — Malicious RSU",
}
COLORS = {"1": "#f28e2b", "2": "#e15759", "3": "#4e79a7", "4": "#59a14f", "5": "#b07aa1"}
MARKERS = {"1": "D", "2": "o", "3": "s", "4": "^", "5": "v"}

# ── Load CSV ───────────────────────────────────────────────────────────────────
data = {}   # data[attack_type][pct] = {TP, FP, TN, FN, FPR, MCC, ...}

with open(CSV_PATH, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        atk = row["attack_type"]
        pct = int(row["attack_pct"])
        if atk not in data:
            data[atk] = {}
        try:
            data[atk][pct] = {
                "MCC": float(row["MCC"]),
                "FPR": float(row["FPR"]),
                "MDR": float(row["MDR"]),
                "Precision": float(row["Precision"]),
                "Recall":    float(row["Recall"]),
            }
        except (ValueError, KeyError):
            data[atk][pct] = {"MCC": None, "FPR": None, "MDR": None,
                               "Precision": None, "Recall": None}

attack_types = sorted(data.keys())

def plot_metric(metric_key, ylabel, title, filename, ylim=(0, 1)):
    fig, ax = plt.subplots(figsize=(8, 5))

    for atk in attack_types:
        pcts_sorted = sorted(data[atk].keys())
        xs, ys = [], []
        for pct in pcts_sorted:
            val = data[atk][pct].get(metric_key)
            if val is not None:
                xs.append(pct)
                ys.append(val)
        label = ATTACK_LABELS.get(atk, f"Type {atk}")
        ax.plot(xs, ys,
                color=COLORS.get(atk, "gray"),
                marker=MARKERS.get(atk, "x"),
                linewidth=2, markersize=7,
                label=label)

    ax.set_xlabel("Sybil Attack Percentage (%)", fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_ylim(ylim)
    ax.legend(fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()

    out_path = os.path.join(OUT_DIR, filename)
    fig.savefig(out_path, dpi=150)
    print(f"Saved: {out_path}")
    plt.close(fig)

# ── Graph 1: MCC vs Attack Percentage ─────────────────────────────────────────
plot_metric(
    metric_key="MCC",
    ylabel="Matthews Correlation Coefficient (MCC)",
    title="RSSI-Based Sybil Detection — MCC vs Attack Percentage",
    filename="rssi_mcc_vs_pct.png",
    ylim=(-0.2, 1.05),
)

# ── Graph 2: FPR vs Attack Percentage ─────────────────────────────────────────
plot_metric(
    metric_key="FPR",
    ylabel="False Positive Rate (FPR)",
    title="RSSI-Based Sybil Detection — FPR vs Attack Percentage",
    filename="rssi_fpr_vs_pct.png",
    ylim=(0, 1.05),
)

# ── Graph 3 (bonus): MDR vs Attack Percentage ─────────────────────────────────
plot_metric(
    metric_key="MDR",
    ylabel="Miss Detection Rate (MDR)",
    title="RSSI-Based Sybil Detection — MDR vs Attack Percentage",
    filename="rssi_mdr_vs_pct.png",
    ylim=(0, 1.05),
)

print("\nDone. Graphs saved to:", OUT_DIR)
