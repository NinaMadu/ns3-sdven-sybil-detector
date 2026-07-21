"""
Stage-3 STEP 9 (optional) — promote a finished experiment's FINAL global adapters
into a clean, deployable folder for downstream work.

The federated adapters you actually want for "next work" are the LAST round's
GLOBAL adapters of the LLM-FL experiment:
    runs/<exp>/round_<final>/global/{a1,a2,a3}/
This copies those three into one tidy directory and RESTORES the tokenizer (the
18.5 MB training adapters carry only bf16 A/B tensors, no tokenizer), so the result
is a drop-in replacement for the Stage-2 adapter set used by consensus_infer /
the ns-3 real-time daemon.

    ml/.venv/bin/python promote_final.py --exp H0_llm_fl_seed42
    # -> final_models/H0_llm_fl_seed42/{a1,a2,a3}/  + deploy_config.json

Pick which experiment with --exp (default: the converged/last llm_fl run). By
default it promotes the CONVERGED round if Eq 3.73 fired, else the last round.
Use --round to force a specific round.
"""

import argparse
import json
import os
import shutil

import fl_common as F
from fl_common import A
from transformers import AutoTokenizer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(F._HERE, "fl_config.json"))
    ap.add_argument("--exp", required=True, help="experiment id, e.g. H0_llm_fl_seed42")
    ap.add_argument("--round", type=int, default=-1, help="round to promote (-1 = converged/last)")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    base = cfg["base_model"]
    exp = os.path.join(F.RUNS_DIR, args.exp)
    hist = json.load(open(os.path.join(exp, "history.json")))
    if hist["condition"] != "llm_fl":
        raise SystemExit("promote only makes sense for an llm_fl experiment "
                         "(local-only has no single global model)")

    if args.round >= 0:
        rnd = args.round
    elif hist.get("kappa_conv"):
        # κ_conv is the START of the converged 5-round window; the global at that
        # round is a fair 'converged model'. Use it; fall back to last round.
        rnd = hist["kappa_conv"]
    else:
        rnd = hist["rounds_run"]
    src = os.path.join(exp, f"round_{rnd:03d}", "global")
    if not os.path.isdir(src):
        raise SystemExit(f"no global adapters at {src}")

    out = args.out or os.path.join(F._HERE, "final_models", args.exp)
    os.makedirs(out, exist_ok=True)
    tok = AutoTokenizer.from_pretrained(base)
    for a in A.AGENT_ORDER:
        dst = os.path.join(out, a)
        shutil.copytree(os.path.join(src, a), dst, dirs_exist_ok=True)
        tok.save_pretrained(dst)                 # restore tokenizer for deployment

    deploy = {
        "_note": f"Promoted FL global adapters from {args.exp} round {rnd} "
                 f"({hist.get('kappa_conv_note')}). Drop-in for consensus_infer.",
        "base_model": base,
        "adapters": {a: os.path.join(out, a) for a in A.AGENT_ORDER},
        "omega": cfg["eval"]["omega"],
        "theta_consensus": cfg["eval"]["theta_consensus"],
        "source_experiment": args.exp, "source_round": rnd,
        "final_mcc_macro": hist.get("final_mcc_macro"),
        "kappa_conv": hist.get("kappa_conv"),
    }
    json.dump(deploy, open(os.path.join(out, "deploy_config.json"), "w"), indent=2)
    print(f"promoted {args.exp} round {rnd} -> {out}")
    print(f"  a1/a2/a3 global adapters + tokenizer + deploy_config.json")
    print(f"  final_mcc_macro={hist.get('final_mcc_macro')}  {hist.get('kappa_conv_note')}")


if __name__ == "__main__":
    main()
