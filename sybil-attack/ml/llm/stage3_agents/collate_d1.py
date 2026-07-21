"""
Stage-3 STEP 8 — collate the four D1 experiments into one results table.

Reads runs/<endpoint>_<condition>_seed<seed>/history.json for every experiment
found and emits:
  runs/D1_results.md    the paper-ready table (MCC-V, kappa_conv, RC per row)
  runs/D1_results.json  the same data, machine-readable

MCC-V   = final-round mcc_macro (7-class consensus variant vote, Eq 3.64-3.65).
kappa_conv = Eq 3.73 (LLM-FL: global curve; local-only: 4 per-zone rounds + summary).
RC      = final-round rc_mean (Eq 3.74 proxy; see evaluate_round.RC_SIGNATURES).

Run:  ml/.venv/bin/python collate_d1.py
"""

import glob
import json
import os

import fl_common as F

ENDPOINTS = {"H0": "50/50/50/50", "Hmax": "10/30/50/70"}
COND = {"local": "Local-only", "llm_fl": "LLM-FL"}


def _final_metrics(hist):
    for h in reversed(hist.get("history", [])):
        if "metrics" in h:                       # llm_fl rows carry full metrics
            return h["metrics"]
    return {}


def _local_final_metrics(exp_dir, rounds_run, n_zones=4):
    """Local-only has 4 separate per-zone detectors (no single model), so binary
    MCC / FPR / RC are averaged across the 4 zones' final-round metrics.json.
    Returns the zone-mean dict plus the raw per-zone lists for transparency."""
    vals = {"binary_mcc": [], "fpr": [], "rc_mean": []}
    rd = os.path.join(exp_dir, f"round_{rounds_run:03d}", "local")
    for z in range(1, n_zones + 1):
        p = os.path.join(rd, f"zone_{z}", "metrics.json")
        if not os.path.exists(p):
            continue
        m = json.load(open(p))
        for k in vals:
            if m.get(k) is not None:
                vals[k].append(m[k])
    mean = {k: (round(sum(v) / len(v), 4) if v else None) for k, v in vals.items()}
    return mean, vals


def main():
    rows = []
    for hp in sorted(glob.glob(os.path.join(F.RUNS_DIR, "*", "history.json"))):
        d = json.load(open(hp))
        per_zone_extra = None
        if d["condition"] == "local":
            fm, per_zone_extra = _local_final_metrics(os.path.dirname(hp), d.get("rounds_run", 0))
        else:
            fm = _final_metrics(d)
        rows.append({
            "endpoint": d["endpoint"], "zone_pcts": ENDPOINTS.get(d["endpoint"], "?"),
            "condition": d["condition"], "seed": d["seed"],
            "mcc_v": d.get("final_mcc_macro"),
            "kappa_conv": d.get("kappa_conv"),
            "kappa_note": d.get("kappa_conv_note"),
            "rc_mean": fm.get("rc_mean"),
            "binary_mcc": fm.get("binary_mcc"),
            "fpr": fm.get("fpr"),
            "per_zone_kappa": d.get("per_zone_kappa_conv"),
            "rounds_run": d.get("rounds_run"),
        })

    rows.sort(key=lambda r: (r["endpoint"], r["condition"], r["seed"]))
    os.makedirs(F.RUNS_DIR, exist_ok=True)
    json.dump(rows, open(os.path.join(F.RUNS_DIR, "D1_results.json"), "w"), indent=2)

    lines = [
        "# Ablation D1 — LLM-FL vs Local-Only across inter-zone heterogeneity",
        "",
        "Independent variable: inter-zone attacker-proportion heterogeneity.",
        "Dependent metrics: MCC-V (7-class consensus MCC_macro), kappa_conv (Eq 3.73),",
        "RC (Eq 3.74 proxy). Both endpoints hold zone size and hyperparameters fixed;",
        "only the per-zone attacker proportion (and, per condition, Eq 3.32) changes.",
        "",
        "| Zone attacker % | Condition | Seed | MCC-V | kappa_conv | RC | binary_MCC | FPR | rounds |",
        "|---|---|---:|---:|---|---:|---:|---:|---:|",
    ]
    for r in rows:
        kc = r["kappa_conv"] if r["kappa_conv"] is not None else f"n/c({r['rounds_run']})"
        lines.append(
            f"| {r['zone_pcts']} | {COND.get(r['condition'], r['condition'])} | {r['seed']} "
            f"| {r['mcc_v']} | {kc} | {r['rc_mean']} | {r['binary_mcc']} | {r['fpr']} | {r['rounds_run']} |")

    # local-only per-zone kappa detail
    detail = [r for r in rows if r["condition"] == "local" and r["per_zone_kappa"]]
    if detail:
        lines += ["", "## Local-only per-zone convergence (kappa_conv per zone)", ""]
        for r in detail:
            pz = ", ".join(f"zone{z}={v}" for z, v in r["per_zone_kappa"].items())
            lines.append(f"- {r['zone_pcts']} seed {r['seed']}: {pz}")

    lines += [
        "", "> Note: for **Local-only** there is no single model — it is four separate",
        "> per-zone detectors, so binary_MCC / FPR / RC are the **mean across the 4 zones**",
        "> (MCC-V is likewise the zone summary). For **LLM-FL** they are the one global model.",
        "", "## Reading this table",
        "- Compare LLM-FL vs Local-only WITHIN each heterogeneity row, then across rows.",
        "- The D1 question is the interaction: does the LLM-FL benefit grow as zones diverge",
        "  (Hmax) versus when they are homogeneous (H0)?",
        "- Overhead (Omega_LLM-FL, zeta_LoRA) is per-round in each run's communication.json;",
        "  it supports the framework claim but is NOT a D1 dependent metric.",
        "- Optionally add the Stage-2 centralized pooled run as a labelled reference row",
        "  (NOT a D1 condition).",
    ]
    out = os.path.join(F.RUNS_DIR, "D1_results.md")
    open(out, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
