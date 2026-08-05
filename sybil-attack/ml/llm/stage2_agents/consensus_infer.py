"""
Reusable, label-free inference core for the Stage-2 three-agent consensus.

This is the shared seam between the OFFLINE evaluator (`consensus_eval.py`, which
has gold labels and recalibrates θ) and the ONLINE real-time detector (the daemon
in ml/serve/, which has no labels and uses FROZEN θ/ω). Both must run the exact
same generation + Eq 3.22 arithmetic, so it lives here once.

Contents:
  load_config()            -> frozen deployment params (ω, θ, conf weights, paths)
  load_agents()            -> one shared base + a1/a2/a3 LoRA adapters
  agent_generate()         -> batched greedy generation, parsed verdict dicts
  build_decision_matrices()-> per-window (D, PT, CF) matrices from parsed preds
  consensus()              -> Eq 3.22 D_global + confidence-weighted variant vote

Nothing here reads a ground-truth label; scoring/metrics stay in consensus_eval.
"""

import copy
import json
import os
import sys
import time

import numpy as np
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
import constants as C          # noqa: E402
import agents as A             # noqa: E402  (AGENT_ORDER, AGENTS)
from eval_fusion import extract_json  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))

# Confidence -> vote weight for the multiclass variant vote (paper §4.6).
CONF_W = {"high": 1.0, "medium": 0.6, "low": 0.3}

# FROZEN deployment defaults — the version-controlled source of truth for the
# real-time detector, baked into this tracked .py so a clean clone is runnable.
# Mirrors the validated scorecards/stage2_consensus.json (consensus MCC 0.9991,
# FPR 0.0). No runtime recalibration. Adapter paths are relative to this file.
FROZEN_DEFAULTS = {
    "base_model": "Qwen/Qwen2.5-1.5B-Instruct",
    "adapters": {"a1": "adapters/qwen1_5b_a1",
                 "a2": "adapters/qwen1_5b_a2",
                 "a3": "adapters/qwen1_5b_a3"},
    "omega": {"a1": 1 / 3, "a2": 1 / 3, "a3": 1 / 3},
    "theta_consensus": 0.6667,
    "confidence_weights": dict(CONF_W),
    "tie_break_agent": "a3",
}

# OPTIONAL machine-local override (gitignored *.json); merged over the defaults if
# present. Nothing is required at runtime — the defaults above already work.
DEFAULT_CONFIG = os.path.join(_HERE, "consensus_config.json")

# ── NAMED AGENT STAGES (the "LLM agent shifter") ──────────────────────────────
# A stage selects ONLY which LoRA adapter triple is overlaid on the shared frozen
# base. Everything else — base model, the three ROLE PROMPTS (Stage-3 training
# imports agents.AGENTS from here, so they are byte-identical), ω, θ, confidence
# weights and tie-break — is inherited from FROZEN_DEFAULTS. That is deliberate:
# switching stages isolates the adapters and nothing else, so a Stage-2 vs
# Stage-3 comparison is attributable to the federation alone.
#
# Both adapter sets are r=8 / α=16 LoRA over the same 7 target modules on the
# same Qwen2.5-1.5B-Instruct base, so they are drop-in interchangeable.
# Paths are relative to THIS file's directory (see load_config).
AGENT_STAGES = {
    # Stage-2: CENTRALLY trained adapters (the frozen deployment default, D5).
    "stage2": {"a1": "adapters/qwen1_5b_a1",
               "a2": "adapters/qwen1_5b_a2",
               "a3": "adapters/qwen1_5b_a3"},
    # Stage-3: FEDERATED adapters, Eq 3.32 aggregation over 4 zones, Hmax
    # partition (10/30/50/70 label skew) — the promoted deployment set (D6).
    "stage3": {"a1": "../stage3_agents/final_models/Hmax_llm_fl_seed42/a1",
               "a2": "../stage3_agents/final_models/Hmax_llm_fl_seed42/a2",
               "a3": "../stage3_agents/final_models/Hmax_llm_fl_seed42/a3"},
    # Stage-3 contingency: same federation under the H0 (IID) zone partition.
    "stage3_h0": {"a1": "../stage3_agents/final_models/H0_llm_fl_seed42/a1",
                  "a2": "../stage3_agents/final_models/H0_llm_fl_seed42/a2",
                  "a3": "../stage3_agents/final_models/H0_llm_fl_seed42/a3"},
}

# Friendly spellings accepted from the CLI / the C++ --llmAgentStage flag.
STAGE_ALIASES = {
    "2": "stage2", "stage2": "stage2", "central": "stage2",
    "3": "stage3", "stage3": "stage3", "hmax": "stage3",
    "stage3_hmax": "stage3", "3hmax": "stage3", "fl": "stage3",
    "3h0": "stage3_h0", "h0": "stage3_h0", "stage3_h0": "stage3_h0",
}

DEFAULT_STAGE = "stage2"   # unchanged behaviour when nothing is selected


def normalize_stage(name):
    """Map a user-supplied stage spelling onto an AGENT_STAGES key.

    Accepts '2'/'3' as well as the canonical 'stage2'/'stage3'/'stage3_h0'.
    Raises ValueError (listing the valid choices) on anything else, so a typo can
    never silently fall back to the Stage-2 default and make a Stage-3 run a
    duplicate of a Stage-2 one.
    """
    key = STAGE_ALIASES.get(str(name).strip().lower())
    if key is None:
        raise ValueError(
            f"unknown LLM agent stage {name!r}; choose one of "
            f"{sorted(AGENT_STAGES)} (aliases: {sorted(STAGE_ALIASES)})")
    return key


def load_config(path=None, stage=None):
    """Frozen consensus config: FROZEN_DEFAULTS + optional JSON override / stage.

    Starts from the version-controlled defaults and, if `path` is given or
    consensus_config.json sits next to this file, shallow-merges that JSON on top
    (keys starting with '_' are ignored). Adapter paths are resolved to absolutes.

    `stage` selects a NAMED adapter set from AGENT_STAGES ('stage2' | 'stage3' |
    'stage3_h0', or the short '2'/'3'). It is applied LAST, so an explicit stage
    always beats the machine-local consensus_config.json — otherwise a stale
    gitignored file on one machine could silently revert a Stage-3 selection back
    to Stage-2 and the run would be mislabelled. Passing both `path` and `stage`
    is rejected as ambiguous rather than resolved by a precedence rule.

    Returns dict: base, adapters{a->abs}, omega[list in AGENT_ORDER], theta,
    conf_w{high/medium/low}, tie_break_idx, stage (human-readable provenance).
    """
    if path and stage:
        raise ValueError(
            "pass EITHER a consensus-config path OR an agent stage, not both "
            f"(got path={path!r}, stage={stage!r}). The stage registry already "
            "names the Stage-2/Stage-3 adapter sets; a path is for a bespoke config.")
    cfg = copy.deepcopy(FROZEN_DEFAULTS)
    override = path or (DEFAULT_CONFIG if os.path.exists(DEFAULT_CONFIG) else None)
    if override:
        with open(override) as f:
            cfg.update({k: v for k, v in json.load(f).items()
                        if not str(k).startswith("_")})
    if stage is not None:
        key = normalize_stage(stage)
        cfg["adapters"] = dict(AGENT_STAGES[key])
        provenance = key
    elif path:
        provenance = f"config:{os.path.basename(path)}"
    elif override:
        provenance = f"{DEFAULT_STAGE}+local:{os.path.basename(override)}"
    else:
        provenance = f"{DEFAULT_STAGE} (FROZEN_DEFAULTS)"
    adapters = {}
    for a in A.AGENT_ORDER:
        p = cfg["adapters"][a]
        adapters[a] = p if os.path.isabs(p) else os.path.normpath(os.path.join(_HERE, p))
    omega = [float(cfg["omega"][a]) for a in A.AGENT_ORDER]
    conf_w = cfg.get("confidence_weights", CONF_W)
    tie = cfg.get("tie_break_agent", "a3")
    return {
        "base": cfg["base_model"],
        "adapters": adapters,
        "omega": omega,
        "theta": float(cfg["theta_consensus"]),
        "conf_w": conf_w,
        "tie_break_idx": A.AGENT_ORDER.index(tie),
        "stage": provenance,
    }


def load_agents(base, adapters, dtype=torch.bfloat16, device=0):
    """Load ONE frozen base + the three LoRA adapters (a1/a2/a3) as named overlays.

    `adapters` is a dict {a1,a2,a3 -> path}. Returns (tok, model) with model.eval().
    Select an agent before generating with model.set_adapter("a1"|"a2"|"a3").
    """
    # Pre-flight: a wrong adapter path otherwise surfaces as an opaque HF "repo id"
    # error deep inside PeftModel, or — worse for the shifter — a partially loaded
    # agent set. Check all three up front and name the offender. Deliberately here
    # and not in load_config, so config-only callers (the eq audit reading ω/θ) keep
    # working on a clone where the gitignored weights are absent.
    for a in A.AGENT_ORDER:
        p = adapters[a]
        if not os.path.isfile(os.path.join(p, "adapter_config.json")):
            raise FileNotFoundError(
                f"LoRA adapter for agent {a} not found: {p}/adapter_config.json is "
                f"missing. Adapter weights are machine-local (gitignored) — check the "
                f"selected agent stage / consensus config points at a materialised set.")
    tok = AutoTokenizer.from_pretrained(adapters["a1"])
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"

    model = AutoModelForCausalLM.from_pretrained(base, dtype=dtype,
                                                 device_map={"": device})
    peft_model = PeftModel.from_pretrained(model, adapters["a1"], adapter_name="a1")
    peft_model.load_adapter(adapters["a2"], adapter_name="a2")
    peft_model.load_adapter(adapters["a3"], adapter_name="a3")
    peft_model.eval()
    return tok, peft_model


def agent_generate(model, tok, prompt_messages, batch, max_new):
    """Greedy-generate a parsed verdict dict per prompt.

    `prompt_messages` is a list of chat-message lists WITHOUT the assistant turn
    (each = [{system}, {user}]); the generation prompt is appended here. Returns
    (preds, dt_seconds, gen_tokens) where preds[i] is the parsed JSON dict or None.
    Identical arithmetic to the original consensus_eval.generate().
    """
    preds, n = [], len(prompt_messages)
    gen_tokens, dt = 0, 0.0
    for start in range(0, n, batch):
        chunk = prompt_messages[start:start + batch]
        prompts = [tok.apply_chat_template(m, add_generation_prompt=True,
                                           tokenize=False) for m in chunk]
        enc = tok(prompts, return_tensors="pt", padding=True).to(model.device)
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        t0 = time.time()
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=max_new, do_sample=False,
                                 pad_token_id=tok.pad_token_id)
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        dt += time.time() - t0
        gen = out[:, enc["input_ids"].shape[1]:]
        gen_tokens += int((gen != tok.pad_token_id).sum().item())
        for text in tok.batch_decode(gen, skip_special_tokens=True):
            preds.append(extract_json(text))
    return preds, dt, gen_tokens


def build_decision_matrices(preds_by_agent, conf_w=None, agent_order=None,
                            attack_classes=None):
    """Turn per-agent parsed preds into (D, PT, CF) numpy matrices.

    preds_by_agent: dict {agent -> list of parsed dicts (or None)} all length n.
    D[i,j] = 1[verdict==sybil]; PT[i,j] = attack_type (unknown -> 'legitimate');
    CF[i,j] = confidence weight. Column order follows agent_order. Identical to the
    inline loop in the original consensus_eval.
    """
    conf_w = conf_w or CONF_W
    agent_order = agent_order or A.AGENT_ORDER
    classes = attack_classes or C.ATTACK_CLASSES
    n = len(preds_by_agent[agent_order[0]])
    D = np.zeros((n, 3), int)
    PT = np.empty((n, 3), object)
    CF = np.zeros((n, 3))
    for j, agent in enumerate(agent_order):
        for i, p in enumerate(preds_by_agent[agent]):
            if p is None:
                PT[i, j] = "legitimate"
                continue
            at = p.get("attack_type")
            at = at if at in classes else "legitimate"
            D[i, j] = 1 if p.get("verdict") == "sybil" else 0
            PT[i, j] = at
            CF[i, j] = conf_w.get(p.get("confidence", "medium"), 0.6)
    return D, PT, CF


def consensus(D, PT, CF, omega, theta, tie_break_idx=2):
    """Eq 3.22 trust-weighted consensus + confidence-weighted multiclass vote.

        D_global(i) = 1[ Σ_a ω_a · D[i,a] ≥ θ ]
        variant(i)  = argmax over firing agents of Σ CF·ω  (ties -> tie_break agent)

    Returns (Dg: np.ndarray[int], yv: list[str]). Identical to the original
    consensus_eval inner closure.
    """
    omega = np.asarray(omega, dtype=float)
    s = D @ omega
    Dg = (s >= theta).astype(int)
    yv = []
    for i in range(len(Dg)):
        if Dg[i] == 0:
            yv.append("legitimate")
            continue
        score = {}
        for j in range(3):
            if D[i, j] == 1 and PT[i, j] != "legitimate":
                score[PT[i, j]] = score.get(PT[i, j], 0) + CF[i, j] * omega[j]
        yv.append(max(score, key=score.get) if score else PT[i, tie_break_idx])
    return Dg, yv
