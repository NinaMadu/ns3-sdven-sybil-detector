"""
Per-class MCC_k (Eq 3.64) — computed DIRECTLY, for every attack variant.

The supervisor's requirement: MCC_k is the primary per-variant metric for
Experiment 5 (per-variant SOTA comparison) and the seven-class results, and it
must be emitted by the evaluation itself rather than reconstructed afterwards
from saved confusion matrices.

Definition. For each class k the labels are binarised one-vs-rest:

    TP_k = #(y_true = k  and  y_pred = k)
    FP_k = #(y_true != k and  y_pred = k)
    FN_k = #(y_true = k  and  y_pred != k)
    TN_k = #(y_true != k and y_pred != k)

    MCC_k = (TP_k·TN_k - FP_k·FN_k)
            / sqrt((TP_k+FP_k)(TP_k+FN_k)(TN_k+FP_k)(TN_k+FN_k))

with MCC_k = 0 when the denominator is 0 (a class never predicted and never
present, or predicted for every window). Absent classes are reported with
support 0 and flagged, never silently dropped — class 6 (malicious_controller)
has no vehicle-tier windows by construction.

Two ways to use it:

1. As a library — this is how `evaluate_round.py` emits MCC_k directly:
       from per_class_mcc import per_class_mcc
       m = per_class_mcc(y_true, y_pred)          # {class: {mcc, support, ...}}

2. As a CLI over any saved per-window prediction table (works for the other
   tiers too, not just the LLM layer):
       python per_class_mcc.py --preds <file.parquet> \
              --true-col true_attack_type --pred-col variant_vote \
              --label full_mode_qwen --out scorecards/
"""

import argparse
import json
import math
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "common"))
import constants as C          # noqa: E402  the authoritative 7-class taxonomy


def _mcc_from_counts(tp, fp, fn, tn):
    """Binary MCC from a 2x2 count table; 0 when the denominator vanishes."""
    num = (tp * tn) - (fp * fn)
    den = math.sqrt(float(tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return 0.0 if den == 0 else num / den


def per_class_mcc(y_true, y_pred, classes=None):
    """One-vs-rest MCC_k plus the supporting counts, for every class.

    y_true / y_pred: sequences of class labels (str or int, must match).
    classes: label list; defaults to the canonical 7-class taxonomy.
    Returns {class_name: {mcc, precision, recall, f1, support, tp, fp, fn, tn}}.
    """
    classes = classes or C.ATTACK_CLASSES
    y_true = list(y_true)
    y_pred = list(y_pred)
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} vs {len(y_pred)}")
    n = len(y_true)

    out = {}
    for k in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == k and p == k)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != k and p == k)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == k and p != k)
        tn = n - tp - fp - fn
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[k] = {
            "mcc": round(_mcc_from_counts(tp, fp, fn, tn), 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": tp + fn,                     # true occurrences of k
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "present_in_data": (tp + fn) > 0,
        }
    return out


def summarise(pcm, classes=None):
    """Macro-average MCC_k over the classes actually present in the data.

    Reported both ways: over present classes only (the meaningful average) and
    over all 7 (which absent classes drag toward 0). State which one a table uses.
    """
    classes = classes or C.ATTACK_CLASSES
    present = [k for k in classes if pcm[k]["present_in_data"]]
    m_present = [pcm[k]["mcc"] for k in present]
    m_all = [pcm[k]["mcc"] for k in classes]
    return {
        "macro_mcc_present_classes": round(sum(m_present) / len(m_present), 4) if m_present else None,
        "n_present_classes": len(present),
        "macro_mcc_all_classes": round(sum(m_all) / len(m_all), 4),
        "n_all_classes": len(classes),
        "absent_classes": [k for k in classes if not pcm[k]["present_in_data"]],
    }


def markdown_table(pcm, classes=None):
    classes = classes or C.ATTACK_CLASSES
    lines = ["| Variant | MCC_k | Precision | Recall | F1 | Support |",
             "|---|---:|---:|---:|---:|---:|"]
    for k in classes:
        r = pcm[k]
        mcc = f"{r['mcc']:.4f}" if r["present_in_data"] else "n/a*"
        lines.append(f"| {k} | {mcc} | {r['precision']:.4f} | {r['recall']:.4f} "
                     f"| {r['f1']:.4f} | {r['support']} |")
    if any(not pcm[k]["present_in_data"] for k in classes):
        lines.append("")
        lines.append("\\* class has zero windows in the evaluation set "
                     "(malicious_controller is a control-plane attack with no "
                     "vehicle-tier beacons, so it is absent by construction).")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preds", required=True, help="parquet/csv with per-window y_true and y_pred")
    ap.add_argument("--true-col", default="true_attack_type")
    ap.add_argument("--pred-col", default="variant_vote")
    ap.add_argument("--label", default="", help="name for this system in the output")
    ap.add_argument("--out", default="", help="directory to write <label>_per_class_mcc.json/.md")
    args = ap.parse_args()

    import pandas as pd
    df = (pd.read_parquet(args.preds) if args.preds.endswith(".parquet")
          else pd.read_csv(args.preds))
    for c in (args.true_col, args.pred_col):
        if c not in df.columns:
            raise SystemExit(f"column '{c}' not in {args.preds}; has {list(df.columns)}")

    pcm = per_class_mcc(df[args.true_col], df[args.pred_col])
    summary = summarise(pcm)
    label = args.label or os.path.basename(args.preds).replace(".parquet", "")

    print(f"\n=== Per-class MCC_k (Eq 3.64) — {label} ===")
    print(f"n = {len(df):,} windows   source = {args.preds}\n")
    print(markdown_table(pcm))
    print("\nmacro MCC_k over present classes :", summary["macro_mcc_present_classes"],
          f"({summary['n_present_classes']} classes)")
    print("macro MCC_k over all 7 classes   :", summary["macro_mcc_all_classes"])
    if summary["absent_classes"]:
        print("absent from evaluation set       :", ", ".join(summary["absent_classes"]))

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        rec = {"label": label, "source": args.preds, "n_eval": len(df),
               "equation": "3.64 (one-vs-rest MCC per class)",
               "per_class": pcm, "summary": summary}
        jp = os.path.join(args.out, f"{label}_per_class_mcc.json")
        mp = os.path.join(args.out, f"{label}_per_class_mcc.md")
        json.dump(rec, open(jp, "w"), indent=2)
        open(mp, "w").write(f"# Per-class MCC_k (Eq 3.64) — {label}\n\n"
                            f"n = {len(df):,} windows\n\n" + markdown_table(pcm) +
                            f"\n\nMacro MCC_k (present classes) = "
                            f"{summary['macro_mcc_present_classes']}\n")
        print(f"\nwrote {jp}\n      {mp}")


if __name__ == "__main__":
    main()
