"""
Stage-3 STEP 5 — evaluate a three-agent adapter set on the FROZEN shared val set.

Reuses the Stage-2 consensus machinery verbatim (consensus_infer.load/generate/
build_decision_matrices/consensus) so a federated round is scored the exact same
way the centralized run was. Difference from consensus_eval.py: theta and omega
are FROZEN from fl_config (no per-round recalibration), so the D1 curve is not
confounded by moving calibration, and it loads the tokenizer from the BASE model
(the bf16 adapters carry no tokenizer, keeping them ~18.5 MB).

Reports, per call, everything Ablation D1 / Eq 3.73 need:
  - mcc_macro    : 7-class multiclass MCC on the consensus variant vote  (Eq 3.73)
  - binary_mcc, fpr, macro_f1, per_class_recall, json_valid_rate
  - rc           : reasoning-evidence consistency, Eq 3.74 (documented proxy; see
                   RC_SIGNATURES + README — confirm I* against the report)

evaluate_global() is importable by run_federation.py; a __main__ wrapper also
allows scoring one adapter triple standalone.
"""

import argparse
import json
import os
import sys

import numpy as np
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

import fl_common as F
from fl_common import C, A
from per_class_mcc import per_class_mcc, summarise   # Eq 3.64, emitted directly
sys.path.insert(0, os.path.join(F._LLM, "stage2_agents"))
import consensus_infer as I     # noqa: E402  (shared generation + Eq 3.22 math)

# ── RC (Eq 3.74) evidence vocabulary and per-class expected signature set I* ──
# Î = evidence categories the agents' reasoning cites; I* = categories that SHOULD
# fire for the true class. RC_attack = |Î∩I*|/|I*|; RC_legit = 1[Î=∅].
# NOTE: this I* map is a documented proxy — confirm against the report's exact
# signature definition before quoting RC as a headline number.
RC_VOCAB = {
    "rssi":     ("rssi", "signal", "mismatch"),
    "trust":    ("trust", "corroboration", "lifetime", "verified", "report"),
    "beacon":   ("beacon", "inter-arrival", "entropy", "cadence"),
    "mobility": ("mobility", "churn", "velocity", "handoff", "rotation"),
    "ensemble": ("ensemble",),
}
RC_SIGNATURES = {
    "legitimate": set(),
    "outsider": {"trust"},
    "sim": {"beacon", "rssi"},
    "nonsim": {"mobility", "trust"},
    "indirect": {"ensemble", "trust"},
    "malicious_rsu": {"ensemble"},
    "malicious_controller": {"ensemble"},
}


def load_triple(base, adapters, device=0):
    """Base + a1/a2/a3 adapters; tokenizer from BASE (adapters carry none)."""
    tok = AutoTokenizer.from_pretrained(base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"
    model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.bfloat16,
                                                 device_map={"": device})
    peft = PeftModel.from_pretrained(model, adapters["a1"], adapter_name="a1")
    peft.load_adapter(adapters["a2"], adapter_name="a2")
    peft.load_adapter(adapters["a3"], adapter_name="a3")
    peft.eval()
    return tok, peft


def _rc_indicators(text):
    t = (text or "").lower()
    return {cat for cat, kws in RC_VOCAB.items() if any(k in t for k in kws)}


def _rc(true_label, reasonings):
    """reasonings: list of the fired agents' reasoning strings for this window."""
    seen = set()
    for r in reasonings:
        seen |= _rc_indicators(r)
    istar = RC_SIGNATURES.get(true_label, set())
    if not istar:                                  # legitimate: no signature should fire
        return 1.0 if not seen else 0.0
    return len(seen & istar) / len(istar)


def _load_split(agent, split):
    path = os.path.join(F.DATA_DIR, "shared", agent, f"{split}.jsonl")
    return [json.loads(l) for l in open(path)]


def score(gold, D, PT, CF, preds, omega, theta):
    from sklearn.metrics import (matthews_corrcoef, f1_score, recall_score)
    yt = [1 if g["verdict"] == "sybil" else 0 for g in gold]
    yt_mc = [g["attack_type"] for g in gold]
    Dg, yv = I.consensus(D, PT, CF, omega, theta)

    fp = sum(1 for a, b in zip(yt, Dg) if a == 0 and b == 1)
    fpden = sum(1 for a in yt if a == 0)
    labels = C.ATTACK_CLASSES
    # RC: for fired windows use the reasoning of the agents that fired sybil
    rcs = []
    for i, g in enumerate(gold):
        reasons = [preds[a][i].get("reasoning", "") if preds[a][i] else ""
                   for j, a in enumerate(A.AGENT_ORDER) if D[i, j] == 1]
        rcs.append(_rc(g["attack_type"], reasons))
    return {
        "n_eval": len(yt),
        "mcc_macro": round(float(matthews_corrcoef(yt_mc, yv)), 4),
        "binary_mcc": round(float(matthews_corrcoef(yt, Dg)), 4),
        "fpr": round(fp / fpden, 4) if fpden else None,
        "macro_f1": round(float(f1_score(yt_mc, yv, labels=labels,
                                         average="macro", zero_division=0)), 4),
        "per_class_recall": dict(zip(labels, recall_score(
            yt_mc, yv, labels=labels, average=None, zero_division=0).round(4).tolist())),
        "json_valid_rate": round(float(np.mean(
            [preds["a1"][i] is not None for i in range(len(yt))])), 4),
        "rc_mean": round(float(np.mean(rcs)), 4),
    }


def evaluate_global(adapters, cfg, split="val", tok_model=None):
    """adapters: {a1,a2,a3 -> dir}. Returns the metrics dict for `split`."""
    ecfg = cfg["eval"]
    omega = [ecfg["omega"][a] for a in A.AGENT_ORDER]
    theta = ecfg["theta_consensus"]
    lim = ecfg["val_limit"] if split == "val" else ecfg["test_limit"]

    tok, model = tok_model or load_triple(cfg["base_model"], adapters)
    gold, preds = None, {}
    for agent in A.AGENT_ORDER:
        rows = _load_split(agent, split)
        if lim and lim < len(rows):
            rows = rows[:lim]
        if gold is None:
            gold = [json.loads(r["messages"][-1]["content"]) for r in rows]
        model.set_adapter(agent)
        p, _dt, _n = I.agent_generate(model, tok, [r["messages"][:-1] for r in rows],
                                      ecfg["gen_batch"], ecfg["max_new_tokens"])
        preds[agent] = p
    D, PT, CF = I.build_decision_matrices(preds)
    m = score(gold, D, PT, CF, preds, omega, theta)
    return m, (tok, model)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(F._HERE, "fl_config.json"))
    ap.add_argument("--a1", required=True)
    ap.add_argument("--a2", required=True)
    ap.add_argument("--a3", required=True)
    ap.add_argument("--split", default="val")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    cfg = json.load(open(args.config))
    adapters = {"a1": args.a1, "a2": args.a2, "a3": args.a3}
    m, _ = evaluate_global(adapters, cfg, split=args.split)
    print(json.dumps(m, indent=2))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(m, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    main()
