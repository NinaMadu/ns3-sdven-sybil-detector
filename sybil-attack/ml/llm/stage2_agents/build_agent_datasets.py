"""
Build the three per-agent fine-tuning datasets from the shared context table.

Consumes llm/common/context/c_i.parquet (constants.C_I_PARQUET) and emits, for
each agent a1/a2/a3:
    ml/llm/stage2_agents/data_<agent>/{train,val,test}.jsonl   (chat format)

The USER message (the Eq 3.31 context c_i) is IDENTICAL across agents — per §4.6.2
the three agents process the same shared context. Only the SYSTEM prompt (role) and
the assistant REASONING target differ, so each LoRA adapter specializes on its own
evidence while all three stay label-consistent (7-class). This reuses the Stage-1
context builder and FP-safe balancing verbatim.

Run in ml/.venv:  python ml/fullmode/build_agent_datasets.py
"""

import argparse
import json
import os

import pandas as pd

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import constants as C          # noqa: E402  (constants + build_llm_dataset live in llm/common)
import build_llm_dataset as B          # build_context, balance_train (reused verbatim)
import agents as A

_HERE = os.path.dirname(os.path.abspath(__file__))
DEF_IN = C.C_I_PARQUET          # canonical cᵢ in llm/common/context (path hub)


def agent_target(agent, label, ci):
    """Same schema as Stage-1 build_target, but reasoning is agent-specialized."""
    is_sybil = label != "legitimate"
    ps = ci.get("features", {}).get("temporal", {}).get("p_sybil")
    conf = "high" if ps is not None and (ps > 0.8 or ps < 0.2) else "medium"
    return {"verdict": "sybil" if is_sybil else "legitimate",
            "attack_type": label, "confidence": conf,
            "reasoning": A.agent_reasoning(agent, label, ci)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", default=DEF_IN)
    ap.add_argument("--balance", action="store_true", default=True)
    ap.add_argument("--no-balance", dest="balance", action="store_false")
    args = ap.parse_args()

    df = pd.read_parquet(args.context)
    df["_label"] = df["attack_type"].map(C.class_name)

    tr = df[df["split"] == "train"].copy()
    if args.balance:
        tr = B.balance_train(tr)
    emit = pd.concat([tr, df[df["split"] == "val"], df[df["split"] == "test"]],
                     ignore_index=True)

    # pre-build the shared context JSON once per row (identical for all agents)
    ctx = [(B.build_context(row), row["_label"], row["split"]) for _, row in emit.iterrows()]

    for agent in A.AGENT_ORDER:
        sysmsg = A.AGENTS[agent]["system"]
        outdir = os.path.join(_HERE, f"data_{agent}")
        os.makedirs(outdir, exist_ok=True)
        fhs = {s: open(os.path.join(outdir, f"{s}.jsonl"), "w") for s in ("train", "val", "test")}
        counts = {"train": 0, "val": 0, "test": 0}
        for ci, label, split in ctx:
            user = json.dumps(ci)
            asst = json.dumps(agent_target(agent, label, ci))
            fhs[split].write(json.dumps({"messages": [
                {"role": "system", "content": sysmsg},
                {"role": "user", "content": user},
                {"role": "assistant", "content": asst}]}) + "\n")
            counts[split] += 1
        for fh in fhs.values():
            fh.close()
        print(f"[{agent}] {A.AGENTS[agent]['name']:32s} -> {outdir}  {counts}")


if __name__ == "__main__":
    main()
