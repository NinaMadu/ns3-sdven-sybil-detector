#!/usr/bin/env python
"""Standing check that the LLM agent shifter is wired CORRECTLY and INDEPENDENTLY.

Two properties, asserted together because they only mean something together:

  CORRECT     — 'stage3' resolves to the CONVERGED round-46 federated adapters in
                ml/llm/stage3_agents_new/, at every entry point that can select them
                (the named stage registry AND the D-stack consensus-config JSONs).

  INDEPENDENT — selecting a stage changes the ADAPTERS AND NOTHING ELSE, and the
                Stage-3 set is never reachable by default. Anything that does not
                explicitly ask for stage 3 (bare load_config, the daemon with no
                --agent-stage, the offline evaluators, the C2/C3 ablations) must
                land on the Stage-2 centrally trained adapters.

Config-only: loads no weights and needs no GPU. Run after touching AGENT_STAGES,
the D_stack configs, or the daemon's selector flags.

    python ml/llm/stage2_agents/verify_agent_stage_wiring.py
"""

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import consensus_infer as CI          # noqa: E402
sys.path.insert(0, os.path.join(_HERE, "..", "common"))
import agents as A                    # noqa: E402

_SYBIL = os.path.normpath(os.path.join(_HERE, "..", "..", ".."))
_D_STACK = os.path.join(_SYBIL, "ablation", "D_stack", "configs")

STAGE2_DIR = os.path.join(_HERE, "adapters")
STAGE3_DIR = os.path.normpath(os.path.join(_HERE, "..", "stage3_agents_new",
                                           "final_models", "Hmax_llm_fl_seed42"))
STAGE3_H0_DIR = os.path.normpath(os.path.join(_HERE, "..", "stage3_agents",
                                              "final_models", "H0_llm_fl_seed42"))
# The un-converged round-5 promotion. Kept on disk as the provenance of published
# pre-2026-08-07 Stage-3 numbers; NOTHING selectable may still resolve to it.
RETIRED_DIR = os.path.normpath(os.path.join(_HERE, "..", "stage3_agents",
                                            "final_models", "Hmax_llm_fl_seed42"))

_fails = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not ok:
        _fails.append(name)


def under(cfg, root):
    """True iff all three resolved adapter paths sit under `root`."""
    r = os.path.realpath(root) + os.sep
    return all(os.path.realpath(p).startswith(r) for p in cfg["adapters"].values())


def materialised(cfg):
    return all(os.path.isfile(os.path.join(p, "adapter_config.json"))
               and os.path.isfile(os.path.join(p, "adapter_model.safetensors"))
               for p in cfg["adapters"].values())


def _argparse_defaults(path):
    """{flag: default} for the ap.add_argument calls in a script, without importing it."""
    import ast
    out = {}
    for node in ast.walk(ast.parse(open(path).read())):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and node.args):
            continue
        flag = node.args[0]
        if not (isinstance(flag, ast.Constant) and isinstance(flag.value, str)):
            continue
        for kw in node.keywords:
            if kw.arg == "default":
                try:
                    out[flag.value] = ast.literal_eval(kw.value)
                except ValueError:
                    out[flag.value] = "<expr>"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--require-weights", action="store_true",
                    help="also fail if the (gitignored) adapter weights are absent; "
                         "off by default so a clean clone can still run the check")
    args = ap.parse_args()

    print("\n1. STAGE-3 IS NOT REACHABLE BY DEFAULT")
    # Bare call, exactly what every non-stage-aware caller does.
    d = CI.load_config()
    check("load_config() -> Stage-2 adapters", under(d, STAGE2_DIR), d["stage"])
    check("load_config() names no stage3 path",
          not any("stage3" in p for p in d["adapters"].values()))
    # Same with the gitignored machine-local override taken out of the picture, so
    # the guarantee comes from FROZEN_DEFAULTS and not from one machine's JSON.
    saved, CI.DEFAULT_CONFIG = CI.DEFAULT_CONFIG, os.path.join(_HERE, "__absent__.json")
    try:
        f = CI.load_config()
        check("load_config() w/o local override -> Stage-2", under(f, STAGE2_DIR), f["stage"])
        check("FROZEN_DEFAULTS name no stage3 path",
              not any("stage3" in p for p in CI.FROZEN_DEFAULTS["adapters"].values()))
    finally:
        CI.DEFAULT_CONFIG = saved
    check("DEFAULT_STAGE is stage2", CI.DEFAULT_STAGE == "stage2", CI.DEFAULT_STAGE)

    print("\n2. EXPLICIT SELECTION RESOLVES TO THE RIGHT SET")
    cases = [(["2", "stage2", "central"], STAGE2_DIR, "Stage-2 central"),
             (["3", "stage3", "hmax", "stage3_hmax", "3hmax", "fl"], STAGE3_DIR,
              "Stage-3 FL Hmax (stage3_agents_new, round 46)"),
             (["stage3_h0", "h0", "3h0"], STAGE3_H0_DIR, "Stage-3 FL H0 (unchanged)")]
    for aliases, root, label in cases:
        for al in aliases:
            c = CI.load_config(stage=al)
            check(f"stage={al!r} -> {label}", under(c, root), c["stage"])
    # Every alias in the registry must be covered above, so a newly added spelling
    # cannot slip through this check untested.
    covered = {a for aliases, _, _ in cases for a in aliases}
    check("all STAGE_ALIASES covered by this check",
          covered == set(CI.STAGE_ALIASES), str(sorted(set(CI.STAGE_ALIASES) - covered)))

    print("\n3. THE RETIRED ROUND-5 SET IS NO LONGER SELECTABLE")
    for key in CI.AGENT_STAGES:
        c = CI.load_config(stage=key)
        check(f"stage={key!r} avoids the retired round-5 dir", not under(c, RETIRED_DIR))

    print("\n4. SELECTION IS INDEPENDENT — ONLY THE ADAPTERS MOVE")
    ref = CI.load_config(stage="stage2")
    for key in CI.AGENT_STAGES:
        c = CI.load_config(stage=key)
        same = (c["base"] == ref["base"] and c["omega"] == ref["omega"]
                and c["theta"] == ref["theta"] and c["conf_w"] == ref["conf_w"]
                and c["tie_break_idx"] == ref["tie_break_idx"])
        check(f"stage={key!r} inherits base/omega/theta/conf/tie-break", same,
              f"theta={c['theta']} omega={c['omega'][0]:.4f} base={c['base']}")
        check(f"stage={key!r} adapters differ from Stage-2" if key != "stage2"
              else "stage2 is its own reference",
              (c["adapters"] != ref["adapters"]) if key != "stage2" else True)

    print("\n5. THE D-STACK CONFIG JSONs AGREE WITH THE REGISTRY")
    # README states configs/llm_fl_hmax.json and --llmAgentStage=3 are the same set;
    # they are separate files, so drift between them is possible and worth asserting.
    for fname, root, label in [("llm_fl_hmax.json", STAGE3_DIR, "Stage-3 Hmax (new)"),
                               ("llm_fl_h0.json", STAGE3_H0_DIR, "Stage-3 H0")]:
        p = os.path.join(_D_STACK, fname)
        if not os.path.exists(p):
            check(f"{fname} present", False, p)
            continue
        c = CI.load_config(path=p)
        check(f"{fname} -> {label}", under(c, root), c["stage"])
    ph = CI.load_config(path=os.path.join(_D_STACK, "llm_fl_hmax.json"))
    check("llm_fl_hmax.json == AGENT_STAGES['stage3']",
          ph["adapters"] == CI.load_config(stage="3")["adapters"])

    print("\n6. THE TWO SELECTORS STAY MUTUALLY EXCLUSIVE")
    try:
        CI.load_config(path=os.path.join(_D_STACK, "llm_fl_hmax.json"), stage="3")
        check("load_config(path=..., stage=...) rejected", False)
    except ValueError:
        check("load_config(path=..., stage=...) rejected", True)
    try:
        CI.normalize_stage("stage4")
        check("unknown stage name rejected", False)
    except ValueError:
        check("unknown stage name rejected", True)

    print("\n7. STAGE-3 IS DROP-IN FOR STAGE-2 (same LoRA geometry)")
    ranks = {}
    for key in CI.AGENT_STAGES:
        c = CI.load_config(stage=key)
        for a in A.AGENT_ORDER:
            f = os.path.join(c["adapters"][a], "adapter_config.json")
            if not os.path.isfile(f):
                continue
            j = json.load(open(f))
            ranks.setdefault((key, a), (j.get("r"), j.get("lora_alpha"),
                                        tuple(sorted(j.get("target_modules", []))),
                                        j.get("base_model_name_or_path")))
    if ranks:
        s2 = {a: ranks.get(("stage2", a)) for a in A.AGENT_ORDER}
        for (key, a), v in sorted(ranks.items()):
            if key == "stage2" or s2[a] is None:
                continue
            check(f"{key}/{a} r/alpha/targets/base match Stage-2/{a}", v == s2[a],
                  f"r={v[0]} alpha={v[1]}")
    else:
        check("adapter configs readable (weights are machine-local)",
              not args.require_weights, "no adapter_config.json found")

    print("\n8. THE ENTRY POINTS DEFAULT TO STAGE-2")
    # AST-parsed rather than imported: importing the daemon drags in torch/CUDA and
    # would make a config-only check cost a model load.
    daemon = os.path.join(_SYBIL, "ml", "serve", "rt_full_mode_daemon.py")
    defaults = _argparse_defaults(daemon)
    for flag in ("--agent-stage", "--consensus-config"):
        check(f"daemon {flag} defaults to None", defaults.get(flag, "MISSING") is None,
              repr(defaults.get(flag, "MISSING")))
    # The offline evaluators and the C/D ablations take adapter dirs positionally;
    # their DEFAULTS must be the Stage-2 set, or an unflagged rerun silently
    # becomes a Stage-3 run.
    for rel in ("ablation/C2/rerun_three_agent_with_reasoning.py",
                "ablation/C3/c3_eval.py"):
        p = os.path.join(_SYBIL, rel)
        if not os.path.exists(p):
            continue
        src = open(p).read()
        check(f"{os.path.basename(rel)} --adapters default is Stage-2",
              "stage3" not in src.split("--adapters", 1)[-1].split("ap.add_argument", 1)[0])

    if args.require_weights:
        print("\n9. WEIGHTS MATERIALISED")
        for key in CI.AGENT_STAGES:
            check(f"stage={key!r} weights on disk", materialised(CI.load_config(stage=key)))

    print()
    if _fails:
        print(f"FAILED ({len(_fails)}): " + "; ".join(_fails))
        return 1
    print("All wiring checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
