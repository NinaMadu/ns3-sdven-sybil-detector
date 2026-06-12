#!/usr/bin/env python3
"""
plot_metrics.py
===============
Parse ns-3 SDVEN Sybil simulation results and produce one graph per
evaluation metric (M1-M10 + MCC, FPR, MDR, Precision, Recall).

Each graph shows ALL attack types as separate lines across attack percentages.
A combined overview image is also saved.

Usage (from the ns3-sdven-sybil-detector project root):
    pip install matplotlib numpy          # once
    python3 sybil-attack/scripts/plot_metrics.py
"""

import os
import re
import sys
import math
import matplotlib
matplotlib.use("Agg")          # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR  = os.path.join(_HERE, "..", "results")
GRAPHS_DIR   = os.path.join(_HERE, "..", "graphs")

# ── Experiment grid ───────────────────────────────────────────────────────────
ATTACK_TYPES = {
    1: "Outsider Sybil",
    2: "Insider Direct\nSimultaneous",
    3: "Insider Direct\nNon-Simultaneous",
    4: "Insider Indirect",
}
ATTACK_PERCENTAGES = [0, 10, 25, 50, 75]

# ── Visuals ───────────────────────────────────────────────────────────────────
COLORS  = ["#1565C0", "#C62828", "#2E7D32", "#E65100"]
MARKERS = ["o",       "s",       "^",        "D"      ]
LINE_W  = 2.2
MARKER_S = 8

# ── N_Vehicles detection ─────────────────────────────────────────────────────

_CC_FILE = os.path.join(_HERE, "..", "..", "scratch", "Sybil-Developing-Improved.cc")

def get_n_vehicles() -> int:
    """
    Three-stage lookup for N_Vehicles:
      1. Parse the declaration from Sybil-Developing-Improved.cc
      2. Read from the 0%-attack result file (ids= at first detection round)
      3. Fall back to the hardcoded default (8)
    """
    # Stage 1 — source file
    try:
        with open(_CC_FILE) as fh:
            text = fh.read()
        m = re.search(r"N_Vehicles\s*=\s*(\d+)\s*;", text)
        if m:
            return int(m.group(1))
    except OSError:
        pass

    # Stage 2 — result file for 0 % attack (any type); first RSSI line: ids=N mmse=0
    for atype in (1, 2, 3, 4):
        path = os.path.join(RESULTS_DIR, f"result_type{atype}_pct0.txt")
        try:
            with open(path) as fh:
                text = fh.read()
            m = re.search(r"\[RssiSybilDetector\]\s+t=\S+\s+ids=(\d+)\s+mmse=0", text)
            if m:
                return int(m.group(1))
        except OSError:
            pass

    # Stage 3 — hard-coded fallback
    return 8

N_VEHICLES = get_n_vehicles()

def n_attackers(pct: int) -> int:
    """Actual attacker count = floor(N_Vehicles × pct / 100)."""
    return N_VEHICLES * pct // 100

def pct_xlabel(pct: int) -> str:
    """Build an x-axis tick label like '25%\n(2 att.)'."""
    n = n_attackers(pct)
    if pct == 0:
        return "0%\n(no attack)"
    return f"{pct}%\n({n} att.)"

PCT_LABELS = [pct_xlabel(p) for p in ATTACK_PERCENTAGES]

# ── Metric regex patterns ─────────────────────────────────────────────────────
# Each pattern captures the primary numeric value for that metric.
PATTERNS = {
    "mcc":        re.compile(r"M5 MCC\s*:\s*([-\d.]+)"),
    "fpr":        re.compile(r"M6 FPR\s*:\s*([\d.]+)"),
    "mdr":        re.compile(r"MDR\s*:\s*([\d.]+)"),
    "precision":  re.compile(r"Precision\s*:\s*([\d.]+)"),
    "recall":     re.compile(r"Recall\s*:\s*([\d.]+)"),
    "tp":         re.compile(r"TP=(\d+)"),
    "fp":         re.compile(r"FP=(\d+)"),
    "fn":         re.compile(r"FN=(\d+)"),
    "tn":         re.compile(r"TN=(\d+)"),
    "pdr":        re.compile(r"M1 PDR\s*:\s*([\d.]+)"),
    "latency":    re.compile(r"M2 Latency\s*:\s*([\d.]+)\s*ms"),
    "attraction": re.compile(r"M3 Attraction:\s*([\d.]+)"),
    "congestion": re.compile(r"M4 Congestion:\s*([\d.]+)"),
    "revocation": re.compile(r"M7 Revocation:\s*([\d.]+)\s*ms"),
    "overhead":   re.compile(r"M8 Overhead\s*:\s*([\d.]+)\s*KB"),
    "fl_rounds":  re.compile(r"M9 FL rounds\s*:\s*(\d+)"),
    "flops":      re.compile(r"M10 Complexity:\s*([\d.]+)\s*FLOPs"),
    "wall_ms":    re.compile(r"M10 Complexity:.*?\s([\d.]+)\s*ms/event"),
}

# ── Metric display configuration ──────────────────────────────────────────────
METRICS = [
    # key          long title                                   y-label              y-lim          fmt
    ("pdr",        "M1 — Packet Delivery Ratio (PDR)",          "PDR",               (0.0, 1.05),   ".3f"),
    ("latency",    "M2 — End-to-End Latency",                   "Latency (ms)",      (0,   None),   ".2f"),
    ("attraction", "M3 — Packet Attraction Ratio",              "Attraction Ratio",  (0,   None),   ".2f"),
    ("congestion", "M4 — Congestion Ratio",                     "Congestion Ratio",  (0,   None),   ".2f"),
    ("mcc",        "M5 — Matthews Correlation Coeff. (MCC)",    "MCC",               (-1,  1),      ".3f"),
    ("fpr",        "M6 — False Positive Rate (FPR)",            "FPR",               (0.0, 1.05),   ".3f"),
    ("mdr",        "Miss Detection Rate (MDR)",                  "MDR",               (0.0, 1.05),   ".3f"),
    ("precision",  "Precision",                                  "Precision",         (0.0, 1.05),   ".3f"),
    ("recall",     "Recall (True Positive Rate)",               "Recall",            (0.0, 1.05),   ".3f"),
    ("revocation", "M7 — Revocation Latency",                   "Latency (ms)",      (0,   None),   ".2f"),
    ("overhead",   "M8 — Communication Overhead",               "KB / event",        (0,   None),   ".4f"),
    ("fl_rounds",  "M9 — FL Convergence Rounds",                "Rounds",            (0,   None),   ".0f"),
    ("flops",      "M10 — Computational Complexity",            "FLOPs / event",     (0,   None),   ".0f"),
    ("wall_ms",    "M10 — Wall-Clock Time per Detection",       "ms / event",        (0,   None),   ".3f"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_file(path: str) -> dict:
    """Return a dict of metric_key → float for one result file."""
    try:
        with open(path) as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}
    out = {}
    for key, pat in PATTERNS.items():
        m = pat.search(text)
        out[key] = float(m.group(1)) if m else float("nan")
    return out


def load_all() -> dict:
    """
    Returns nested dict:  data[attack_type][attack_pct] = {metric: value, ...}
    """
    data = {}
    for atype in ATTACK_TYPES:
        data[atype] = {}
        for pct in ATTACK_PERCENTAGES:
            path = os.path.join(RESULTS_DIR, f"result_type{atype}_pct{pct}.txt")
            parsed = parse_file(path)
            if not parsed:
                print(f"  [WARN] missing: {path}")
                parsed = {k: float("nan") for k in PATTERNS}
            data[atype][pct] = parsed
    return data


def _apply_ylim(ax, ylim):
    lo, hi = ylim
    if lo is not None:
        ax.set_ylim(bottom=lo)
    if hi is not None:
        ax.set_ylim(top=hi)


def style_ax(ax, title, xlabel, ylabel, ylim, small=False):
    fs = 9 if small else 12
    ax.set_title(title, fontsize=fs, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=9 if small else 10)
    ax.set_ylabel(ylabel, fontsize=9 if small else 10)
    ax.set_xticks(range(len(ATTACK_PERCENTAGES)))
    ax.set_xticklabels(PCT_LABELS, fontsize=7 if small else 9)
    ax.tick_params(labelsize=7 if small else 9)
    ax.grid(True, linestyle="--", alpha=0.45, linewidth=0.8)
    _apply_ylim(ax, ylim)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

# ── Individual metric graphs ──────────────────────────────────────────────────

def plot_single(key, title, ylabel, ylim, fmt, data, out_dir):
    fig, ax = plt.subplots(figsize=(9, 5.5))

    x = list(range(len(ATTACK_PERCENTAGES)))   # 0,1,2,3,4 — positional

    for idx, (atype, label) in enumerate(ATTACK_TYPES.items()):
        y = [data[atype][pct].get(key, float("nan")) for pct in ATTACK_PERCENTAGES]
        ax.plot(
            x, y,
            color=COLORS[idx], marker=MARKERS[idx],
            linewidth=LINE_W, markersize=MARKER_S,
            label=f"Type {atype}: {label.replace(chr(10), ' ')}",
            zorder=3,
        )
        # annotate data points
        for xi, y_val in zip(x, y):
            if not math.isnan(y_val):
                ax.annotate(
                    f"{y_val:{fmt}}",
                    (xi, y_val),
                    textcoords="offset points", xytext=(0, 8),
                    fontsize=7, ha="center", color=COLORS[idx],
                )

    style_ax(ax, title, f"Attack Percentage  (N={N_VEHICLES} vehicles)", ylabel, ylim)
    ax.legend(fontsize=9, loc="best", framealpha=0.85)

    # subtitle with actual attacker counts
    counts = "  |  ".join(
        f"{p}% → {n_attackers(p)} att." for p in ATTACK_PERCENTAGES if p > 0
    )
    fig.text(0.5, 0.01, counts, ha="center", fontsize=8, color="#555555")

    fig.tight_layout(rect=[0, 0.04, 1, 1])

    fname = os.path.join(out_dir, f"metric_{key}.png")
    fig.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return fname

# ── Combined overview ─────────────────────────────────────────────────────────

def plot_overview(data, out_dir):
    n_cols = 4
    n_rows = math.ceil(len(METRICS) / n_cols)
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(24, 5.5 * n_rows))
    axes_flat = axes.flatten()

    x = list(range(len(ATTACK_PERCENTAGES)))

    for i, (key, title, ylabel, ylim, fmt) in enumerate(METRICS):
        ax = axes_flat[i]
        for idx, (atype, label) in enumerate(ATTACK_TYPES.items()):
            y = [data[atype][pct].get(key, float("nan")) for pct in ATTACK_PERCENTAGES]
            ax.plot(
                x, y,
                color=COLORS[idx], marker=MARKERS[idx],
                linewidth=1.6, markersize=5,
                label=f"T{atype}",
            )
        short = title.split("—")[-1].strip()
        style_ax(ax, short, f"Attack % (N={N_VEHICLES})", ylabel, ylim, small=True)

    # hide spare axes
    for j in range(len(METRICS), len(axes_flat)):
        axes_flat[j].set_visible(False)

    # shared legend at the bottom
    handles, _ = axes_flat[0].get_legend_handles_labels()
    labels = [f"Type {at}: {lb.replace(chr(10), ' ')}"
              for at, lb in ATTACK_TYPES.items()]
    fig.legend(handles, labels,
               loc="lower center", ncol=4, fontsize=10,
               bbox_to_anchor=(0.5, -0.015), framealpha=0.9)

    fig.suptitle(
        "SDVEN Sybil Detection — All Evaluation Metrics vs. Attack Percentage",
        fontsize=15, fontweight="bold", y=1.01,
    )
    fig.tight_layout(rect=[0, 0.04, 1, 1])

    fname = os.path.join(out_dir, "metrics_overview.png")
    fig.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return fname

# ── Confusion-matrix breakdown graph ─────────────────────────────────────────

def plot_confusion(data, out_dir):
    """Grouped bar chart: TP / FP / FN / TN per attack type at each percentage."""
    fig, axes = plt.subplots(1, len(ATTACK_TYPES), figsize=(22, 5), sharey=False)

    bar_labels = ["TP", "FP", "FN", "TN"]
    bar_colors = ["#2E7D32", "#C62828", "#E65100", "#1565C0"]
    x = np.arange(len(ATTACK_PERCENTAGES))
    w = 0.18

    for col, (atype, label) in enumerate(ATTACK_TYPES.items()):
        ax = axes[col]
        for bi, (bkey, bcolor) in enumerate(zip(["tp", "fp", "fn", "tn"], bar_colors)):
            y = [data[atype][pct].get(bkey, 0) for pct in ATTACK_PERCENTAGES]
            ax.bar(x + (bi - 1.5) * w, y,
                   width=w, color=bcolor, label=bar_labels[bi],
                   alpha=0.85, zorder=3)
        ax.set_title(f"Type {atype}: {label.replace(chr(10), ' ')}",
                     fontsize=10, fontweight="bold")
        ax.set_xlabel(f"Attack %  (N={N_VEHICLES} vehicles)", fontsize=9)
        ax.set_ylabel("Count" if col == 0 else "", fontsize=9)
        ax.set_xticks(x)
        ax.set_xticklabels(PCT_LABELS, fontsize=7)
        ax.grid(True, linestyle="--", alpha=0.4, axis="y")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if col == 0:
            ax.legend(fontsize=8)

    fig.suptitle("Confusion Matrix Breakdown (TP / FP / FN / TN) vs. Attack Percentage",
                 fontsize=13, fontweight="bold")
    fig.tight_layout()

    fname = os.path.join(out_dir, "metric_confusion_matrix.png")
    fig.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return fname

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(GRAPHS_DIR, exist_ok=True)

    print(f"N_Vehicles detected  : {N_VEHICLES}")
    print(f"Attacker counts      : " +
          ", ".join(f"{p}%→{n_attackers(p)}" for p in ATTACK_PERCENTAGES))
    print(f"Loading results from : {RESULTS_DIR}")
    data = load_all()

    print(f"\nGenerating individual graphs → {GRAPHS_DIR}")
    for key, title, ylabel, ylim, fmt in METRICS:
        path = plot_single(key, title, ylabel, ylim, fmt, data, GRAPHS_DIR)
        print(f"  ✓  {os.path.basename(path)}")

    print("\nGenerating confusion matrix breakdown...")
    path = plot_confusion(data, GRAPHS_DIR)
    print(f"  ✓  {os.path.basename(path)}")

    print("\nGenerating combined overview...")
    path = plot_overview(data, GRAPHS_DIR)
    print(f"  ✓  {os.path.basename(path)}")

    print(f"\nAll graphs saved to:  {GRAPHS_DIR}/")
    print("Files produced:")
    for f in sorted(os.listdir(GRAPHS_DIR)):
        if f.endswith(".png"):
            print(f"  {f}")

if __name__ == "__main__":
    main()
