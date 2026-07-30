"""
Generate the LLM-FL convergence figures for the report (Ablation D1 / Experiment 3).

Reads the per-round validation MCC-V curves straight from each experiment's
history.json and emits two print-ready PNGs into figures/:

  fig_convergence_curves.png  - per-round MCC-V progression (the metric the
                                supervisor asked for), two panels: homogeneous
                                and maximally heterogeneous.
  fig_convergence_gap.png     - per-round improvement vs the Eq 3.73 tolerance,
                                showing HOW FAR from convergence the runs are.

Run:  ml/.venv/bin/python plot_convergence.py
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(_HERE, "runs")
FIGS = os.path.join(_HERE, "figures")

# ── validated palette (dataviz reference instance, light mode) ──────────────
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e6e5e1"
C_FL = "#2a78d6"      # categorical slot 1 - LLM-FL
C_LOCAL = "#eb6834"   # categorical slot 2 - Local-Only
TOL_C = "#52514e"

CONV_TOL = 0.001      # Eq 3.73: 5-round window range must fall below this

PANELS = [("H0", "Homogeneous  (zones 50/50/50/50)"),
          ("Hmax", "Maximally heterogeneous  (zones 10/30/50/70)")]
SERIES = [("llm_fl", "LLM-FL", C_FL), ("local", "Local-Only", C_LOCAL)]


def curve(endpoint, condition):
    p = os.path.join(RUNS, f"{endpoint}_{condition}_seed42", "history.json")
    return json.load(open(p))["mcc_macro_curve"]


def _style(ax):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8, linestyle="-", zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
        ax.spines[s].set_linewidth(0.8)
    ax.tick_params(colors=INK_2, labelsize=9, length=0)


def fig_curves():
    """Per-round MCC-V progression. Round 0 (untrained init, MCC-V = 0) is
    excluded from the plotted range so the trained rounds stay legible; it is
    stated in the axis note instead."""
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True)
    fig.patch.set_facecolor(SURFACE)

    for ax, (ep, title) in zip(axes, PANELS):
        _style(ax)
        for cond, label, color in SERIES:
            c = curve(ep, cond)
            x = list(range(1, len(c)))       # rounds 1..5
            y = c[1:]
            ax.plot(x, y, color=color, linewidth=2, marker="o", markersize=7,
                    markeredgecolor=SURFACE, markeredgewidth=2, label=label,
                    zorder=3, clip_on=False)
            # selective direct label: final value only
            ax.annotate(f"{y[-1]:.3f}", (x[-1], y[-1]), textcoords="offset points",
                        xytext=(8, -1), fontsize=9, color=INK, va="center",
                        fontweight="bold" if cond == "llm_fl" else "normal")
        ax.set_title(title, fontsize=10.5, color=INK, pad=10, loc="left")
        ax.set_xlabel("Federated round", fontsize=9.5, color=INK_2)
        ax.set_xticks([1, 2, 3, 4, 5])
        ax.set_xlim(0.8, 5.9)          # headroom for the endpoint labels

    axes[0].set_ylabel("Validation MCC-V  (7-class)", fontsize=9.5, color=INK_2)
    axes[0].set_ylim(0.58, 0.84)
    axes[0].legend(frameon=False, fontsize=9.5, loc="lower right",
                   labelcolor=INK)

    fig.suptitle("Per-round validation MCC-V progression (Ablation D1)",
                 fontsize=12.5, color=INK, x=0.008, ha="left", y=0.99,
                 fontweight="bold")
    fig.text(0.008, 0.015,
             "Round 0 (untrained shared initialisation) = 0.000 and is omitted from the plotted range. "
             "No run satisfies Eq 3.73 within 5 rounds.",
             fontsize=8.5, color=INK_2, ha="left")
    fig.tight_layout(rect=[0, 0.045, 1, 0.94])
    out = os.path.join(FIGS, "fig_convergence_curves.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)
    return out


def fig_gap():
    """Per-round improvement vs the Eq 3.73 tolerance — shows the distance to
    convergence on a log scale."""
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True)
    fig.patch.set_facecolor(SURFACE)

    for ax, (ep, title) in zip(axes, PANELS):
        _style(ax)
        ax.axhline(CONV_TOL, color=TOL_C, linewidth=1.4, zorder=2)
        ax.annotate("Eq 3.73 tolerance (1e-3)", (5.45, CONV_TOL), fontsize=8.5,
                    color=TOL_C, va="bottom", ha="right")
        for cond, label, color in SERIES:
            c = curve(ep, cond)[1:]
            d = [abs(c[i + 1] - c[i]) for i in range(len(c) - 1)]
            x = list(range(2, 2 + len(d)))   # delta attributed to the later round
            ax.plot(x, d, color=color, linewidth=2, marker="o", markersize=7,
                    markeredgecolor=SURFACE, markeredgewidth=2, label=label,
                    zorder=3, clip_on=False)
        ax.set_yscale("log")
        ax.set_title(title, fontsize=10.5, color=INK, pad=10, loc="left")
        ax.set_xlabel("Federated round", fontsize=9.5, color=INK_2)
        ax.set_xticks([2, 3, 4, 5])
        ax.set_xlim(1.8, 5.5)

    axes[0].set_ylabel("Round-to-round |ΔMCC-V|", fontsize=9.5, color=INK_2)
    axes[0].set_ylim(5e-4, 2e-1)
    # sit the legend clear of the tolerance rule at the bottom of the panel
    axes[0].legend(frameon=False, fontsize=9.5, loc="lower left",
                   bbox_to_anchor=(0.02, 0.13), labelcolor=INK)

    fig.suptitle("Distance from the convergence criterion",
                 fontsize=12.5, color=INK, x=0.008, ha="left", y=0.99,
                 fontweight="bold")
    fig.text(0.008, 0.015,
             "All runs remain one to two orders of magnitude above the tolerance at round 5: "
             "the models are still improving, so kappa_conv is reported as not converged.",
             fontsize=8.5, color=INK_2, ha="left")
    fig.tight_layout(rect=[0, 0.045, 1, 0.94])
    out = os.path.join(FIGS, "fig_convergence_gap.png")
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)
    return out


def main():
    os.makedirs(FIGS, exist_ok=True)
    for f in (fig_curves(), fig_gap()):
        print("wrote", f)

    # the underlying numbers, for the report table / caption
    print("\nper-round MCC-V (round 0..5):")
    for ep, _ in PANELS:
        for cond, label, _c in SERIES:
            print(f"  {ep:5s} {label:11s} {[round(v,4) for v in curve(ep, cond)]}")


if __name__ == "__main__":
    main()
