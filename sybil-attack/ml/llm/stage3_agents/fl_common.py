"""
Shared helpers for the Stage-3 LLM-FL harness.

Everything here is a thin wrapper over the EXISTING Stage-2 / common code so the
federated pipeline consumes data and builds training records byte-for-byte the
same way the centralized Stage-2 run did. The ONLY thing Stage-3 adds on top is
the four-zone partition (partition_by_zone.py) and the federation loop; the
context vector, the balancing, the agent role prompts, the LoRA recipe, and the
consensus arithmetic are all imported unchanged.
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_LLM = os.path.abspath(os.path.join(_HERE, ".."))            # ml/llm
_STAGE2 = os.path.join(_LLM, "stage2_agents")

# common/ (constants, build_llm_dataset) and stage2_agents/ (agents, consensus)
sys.path.insert(0, os.path.join(_LLM, "common"))
sys.path.insert(0, _STAGE2)

import constants as C           # noqa: E402
import build_llm_dataset as B   # noqa: E402  build_context, balance_train (verbatim)
import agents as A              # noqa: E402  the 3 role prompts, AGENT_ORDER

# Stage-3 lives in its own runs/ tree; nothing here writes into stage2_agents/.
DATA_DIR = os.path.join(_HERE, "data_fl")
RUNS_DIR = os.path.join(_HERE, "runs")


def agent_target(agent, label, ci):
    """Identical to stage2_agents/build_agent_datasets.agent_target."""
    is_sybil = label != "legitimate"
    ps = ci.get("features", {}).get("temporal", {}).get("p_sybil")
    conf = "high" if ps is not None and (ps > 0.8 or ps < 0.2) else "medium"
    return {"verdict": "sybil" if is_sybil else "legitimate",
            "attack_type": label, "confidence": conf,
            "reasoning": A.agent_reasoning(agent, label, ci)}


def chat_record(agent, ci, label):
    """One {messages:[system,user,assistant]} row, same schema as Stage-2."""
    return {"messages": [
        {"role": "system", "content": A.AGENTS[agent]["system"]},
        {"role": "user", "content": json.dumps(ci)},
        {"role": "assistant", "content": json.dumps(agent_target(agent, label, ci))}]}


def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return len(records)
