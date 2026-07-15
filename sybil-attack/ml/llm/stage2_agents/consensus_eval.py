"""
Eq 3.21 + Eq 3.22 — three-agent inference and trust-weighted SDN consensus.

Loads ONE shared frozen base (paper: "three agents share one base LLM instance")
and attaches the three LoRA adapters a1/a2/a3. For each agent it generates the
decision–reasoning pair over the val + test windows (Eq 3.21), then forms the
global decision by trust-weighted consensus (Eq 3.22):

    d_a(v)   = 1[ verdict_a == "sybil" ]
    D_global = 1[ Σ_a ω_a · d_a(v) ≥ θ_consensus ]

ω_a is initialised uniform (1/3 each — the decentralised monitor would update it
online; here it is fixed and then perturbed for the robustness ablation).
θ_consensus is calibrated on the val split by maximising binary MCC. The 7-class
variant under a positive D_global is a confidence-weighted vote of the firing
agents (ties → a3/temporal).

Emits: scorecards/stage2_a1.json … _a3.json (per agent), stage2_consensus.json
       preds/stage2_agent_preds.parquet (per-window per-agent decisions)

Run in the GPU env:
    python consensus_eval.py --base Qwen/Qwen2.5-1.5B-Instruct \
        --adapters ml/fullmode/adapters/qwen1_5b_a1 ...a2 ...a3
"""

import argparse
import json
import os

import numpy as np
import pandas as pd

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import constants as C          # noqa: E402  (constants + eval_fusion live in llm/common)
import agents as A             # noqa: E402
import consensus_infer as I    # noqa: E402  (shared label-free generation + Eq 3.22 math)
from eval_fusion import dir_size_mb  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))


def load_split(agent, split):
    path = os.path.join(_HERE, f"data_{agent}", f"{split}.jsonl")
    return [json.loads(l) for l in open(path)]


def score_binary(y_true_sybil, d):
    from sklearn.metrics import matthews_corrcoef
    mcc = matthews_corrcoef(y_true_sybil, d)
    fp = sum(1 for yt, yp in zip(y_true_sybil, d) if yt == 0 and yp == 1)
    fpden = sum(1 for yt in y_true_sybil if yt == 0)
    return round(float(mcc), 4), round(fp / fpden, 4) if fpden else None


def score_multiclass(y_true, y_pred):
    from sklearn.metrics import f1_score, matthews_corrcoef, recall_score
    labels = C.ATTACK_CLASSES
    return {
        "mcc": round(float(matthews_corrcoef(y_true, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, labels=labels,
                                         average="macro", zero_division=0)), 4),
        "per_class_recall": dict(zip(labels, recall_score(
            y_true, y_pred, labels=labels, average=None, zero_division=0).round(4).tolist())),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-1.5B-Instruct")
    ap.add_argument("--adapters", nargs=3, required=True,
                    help="a1 a2 a3 adapter dirs (order matters)")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-new", type=int, default=128)
    ap.add_argument("--val-limit", type=int, default=4000, help="0 = all val")
    ap.add_argument("--test-limit", type=int, default=0, help="0 = all test")
    ap.add_argument("--scorecards", default=os.path.join(_HERE, "scorecards"))
    ap.add_argument("--preds", default=os.path.join(_HERE, "preds", "stage2_agent_preds.parquet"))
    args = ap.parse_args()

    adir = dict(zip(A.AGENT_ORDER, args.adapters))

    print(f"Loading shared base {args.base} + 3 LoRA adapters ...")
    tok, model = I.load_agents(args.base, adir)

    # rows are identical context across agents; the SYSTEM prompt differs per agent,
    # so load each agent's own split (system prompt baked into messages).
    def take(rows, lim):
        return rows if not lim or lim >= len(rows) else rows[:lim]

    results = {}   # agent -> dict(split -> parsed preds), plus latency
    gold = {}
    for split, lim in (("val", args.val_limit), ("test", args.test_limit)):
        gold[split] = None
        for agent in A.AGENT_ORDER:
            rows = take(load_split(agent, split), lim)
            if gold[split] is None:
                gold[split] = [json.loads(r["messages"][-1]["content"]) for r in rows]
            model.set_adapter(agent)
            print(f"  [{agent}] generating {split} ({len(rows)}) ...")
            preds, dt, ntok = I.agent_generate(
                model, tok, [r["messages"][:-1] for r in rows], args.batch, args.max_new)
            results.setdefault(agent, {})[split] = preds
            if split == "test":
                results[agent]["_lat"] = {
                    "throughput_windows_per_s_batched": round(len(rows) / dt, 2) if dt else None,
                    "tokens_per_s_batched": round(ntok / dt, 1) if dt else None}

    os.makedirs(args.scorecards, exist_ok=True)

    # ---- per-agent scorecards + decision matrices ---------------------------
    D, PT, CF = {}, {}, {}          # split -> (n, 3) decision / attack-type / conf
    for split in ("val", "test"):
        D[split], PT[split], CF[split] = I.build_decision_matrices(
            {a: results[a][split] for a in A.AGENT_ORDER})

    for j, agent in enumerate(A.AGENT_ORDER):
        yt = [1 if g["verdict"] == "sybil" else 0 for g in gold["test"]]
        yt_mc = [g["attack_type"] for g in gold["test"]]
        mcc, fpr = score_binary(yt, D["test"][:, j].tolist())
        mc = score_multiclass(yt_mc, PT["test"][:, j].tolist())
        jvalid = np.mean([results[agent]["test"][i] is not None for i in range(len(yt))])
        sc = {"agent": agent, "name": A.AGENTS[agent]["name"], "adapter": adir[agent],
              "n_eval": len(yt), "binary_mcc": mcc, "false_positive_rate": fpr,
              "multiclass": mc, "json_valid_rate": round(float(jvalid), 4),
              **results[agent]["_lat"], "adapter_size_mb": dir_size_mb(adir[agent])}
        tmeta = os.path.join(adir[agent], "train_meta.json")
        if os.path.exists(tmeta):
            sc["finetune_wall_s"] = json.load(open(tmeta)).get("finetune_wall_s")
        json.dump(sc, open(os.path.join(args.scorecards, f"stage2_{agent}.json"), "w"), indent=2)
        print(f"  [{agent}] test binary-MCC={mcc} FPR={fpr} mc-MCC={mc['mcc']} json={jvalid:.3f}")

    # ---- Eq 3.22 consensus: uniform ω, θ calibrated on val ------------------
    omega = [1/3, 1/3, 1/3]
    yt_val = [1 if g["verdict"] == "sybil" else 0 for g in gold["val"]]
    from sklearn.metrics import matthews_corrcoef
    best_theta, best_m = 0.5, -1.0
    for theta in sorted(set(np.round(np.arange(0.0, 1.0001, 1/3), 4))):  # {0,1/3,2/3,1}
        Dg, _ = I.consensus(D["val"], PT["val"], CF["val"], omega, theta)
        m = matthews_corrcoef(yt_val, Dg)
        if m > best_m:
            best_theta, best_m = float(theta), m

    yt = [1 if g["verdict"] == "sybil" else 0 for g in gold["test"]]
    yt_mc = [g["attack_type"] for g in gold["test"]]
    Dg, yv = I.consensus(D["test"], PT["test"], CF["test"], omega, best_theta)
    mcc, fpr = score_binary(yt, Dg.tolist())
    mc = score_multiclass(yt_mc, yv)

    # robustness ablation: drop each agent (ω→0, renormalise), re-report test MCC
    ablation = {}
    for j, agent in enumerate(A.AGENT_ORDER):
        w = [0.0 if k == j else 0.5 for k in range(3)]
        Dg2, _ = I.consensus(D["test"], PT["test"], CF["test"], w,
                             best_theta * (sum(w)))  # scale θ to the 2-agent mass
        ablation[f"omega_{agent}=0"] = {"binary_mcc": score_binary(yt, Dg2.tolist())[0]}

    consensus_sc = {
        "base_model": args.base, "agents": {a: adir[a] for a in A.AGENT_ORDER},
        "omega": {a: round(omega[i], 4) for i, a in enumerate(A.AGENT_ORDER)},
        "theta_consensus": best_theta, "val_calibration_mcc": round(float(best_m), 4),
        "n_eval": len(yt),
        "consensus_binary_mcc": mcc, "consensus_false_positive_rate": fpr,
        "consensus_multiclass": mc,
        "per_agent_test_binary_mcc": {a: json.load(open(os.path.join(
            args.scorecards, f"stage2_{a}.json")))["binary_mcc"] for a in A.AGENT_ORDER},
        "robustness_ablation": ablation,
    }
    # comparison line vs Stage-1 single head
    s1 = os.path.join(args.scorecards, "qwen0_5b_v2.json")
    if os.path.exists(s1):
        consensus_sc["stage1_single_head_mcc"] = json.load(open(s1)).get("mcc")

    json.dump(consensus_sc, open(os.path.join(args.scorecards, "stage2_consensus.json"), "w"), indent=2)

    # dump per-window per-agent decision matrix for auditing
    os.makedirs(os.path.dirname(os.path.abspath(args.preds)), exist_ok=True)
    rec = pd.DataFrame({
        "true_attack_type": yt_mc, "true_is_sybil": yt,
        "d_a1": D["test"][:, 0], "d_a2": D["test"][:, 1], "d_a3": D["test"][:, 2],
        "D_global": Dg, "variant_vote": yv})
    rec.to_parquet(args.preds, index=False)

    print("\n=== Stage-2 Consensus (Eq 3.22) ===")
    print(json.dumps(consensus_sc, indent=2))


if __name__ == "__main__":
    main()
