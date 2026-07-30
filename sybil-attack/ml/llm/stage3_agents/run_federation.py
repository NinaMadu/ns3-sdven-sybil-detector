"""
Stage-3 STEP 3-6 — federation orchestrator for ONE experiment.

An experiment = (endpoint, condition, seed), e.g. (H0, llm_fl, 42). It drives the
round loop the supervisor's pseudocode describes and writes a fully-auditable run
tree under runs/<exp_id>/.

Two D1 conditions, IDENTICAL rounds / local budget / seeds / initial adapters —
the ONLY difference is whether Eq 3.32 aggregation runs each round:

  llm_fl : every zone starts each round from the shared GLOBAL adapter, trains
           locally (FedProx), then the controller aggregates the 4 zones -> new
           global. Evaluated on the frozen val set as ONE global 3-agent system.
  local  : every zone keeps its OWN adapter chain across rounds (no aggregation).
           Evaluated per-zone (4 three-agent systems) -> 4 MCC-V + summary.

Round 0 is a fresh, deterministic, SHARED LoRA init (same tensors for both
conditions and all zones) so D1 changes only the federation operation.

Stop rule (Eq 3.73): after each round, if the newest `conv_window` validation
mcc_macro values span < `conv_tol`, record kappa_conv and stop; else continue to
`max_rounds` and report "not converged".

Training and aggregation run as SUBPROCESSES (fresh CUDA context each -> clean
memory); evaluation runs in-process. Nothing here writes into stage2_agents/.

Run one experiment:
  ml/.venv/bin/python run_federation.py --endpoint H0 --condition llm_fl --seed 42
Resume/extend (skips rounds whose adapters already exist):
  ... --resume
Smoke test (tiny: 1 round, few val windows, short train):
  ... --smoke
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

import fl_common as F
from fl_common import A

_PY = sys.executable
_HERE = F._HERE


def sh(cmd, log):
    """Run a subprocess, tee stdout to console + log, raise on failure."""
    print("  $", " ".join(str(c) for c in cmd))
    with open(log, "a") as lf:
        lf.write("$ " + " ".join(str(c) for c in cmd) + "\n")
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lf.write(p.stdout)
    if p.returncode != 0:
        sys.stdout.write(p.stdout[-4000:])
        raise RuntimeError(f"subprocess failed ({p.returncode}): {cmd[:4]} ...")


def zone_manifest(endpoint):
    return json.load(open(os.path.join(F.DATA_DIR, endpoint, "zone_manifest.json")))


def ensure_init(base, lora, seed, log, smoke_args):
    """Create (once) the shared round-0 init adapters for this seed."""
    init_dir = os.path.join(F.RUNS_DIR, f"_init_seed{seed}")
    for agent in A.AGENT_ORDER:
        out = os.path.join(init_dir, agent)
        if os.path.exists(os.path.join(out, "adapter_model.safetensors")):
            continue
        sh([_PY, os.path.join(_HERE, "fedprox_train.py"), "--init-only",
            "--base", base, "--agent", agent, "--out", out,
            "--r", str(lora["r"]), "--alpha", str(lora["alpha"]),
            "--dropout", str(lora["dropout"])], log)
    return init_dir


def kappa_conv(curve, window, tol):
    """First round T whose newest `window` mcc_macro values span < tol (Eq 3.73)."""
    for t in range(len(curve) - window + 1):
        w = curve[t:t + window]
        if max(w) - min(w) < tol:
            return t                        # round index of window start
    return None


def round_lr(lc, rnd):
    """Round-wise learning-rate decay:  lr_t = lr_0 · decay^(t-1).

    Without this, every round restarts the local cosine schedule at the full lr,
    so the federation never globally anneals and the Eq 3.73 plateau is never
    reached. decay = 1.0 reproduces the original (non-decaying) behaviour.
    """
    decay = float(lc.get("lr_decay_per_round", 1.0))
    return float(lc["lr"]) * (decay ** max(0, rnd - 1))


def train_zone(base, endpoint, zone, agent, init_adapter, out, mu, lc, tl, log, smoke, rnd=1):
    cmd = [_PY, os.path.join(_HERE, "fedprox_train.py"),
           "--base", base, "--agent", agent,
           "--data", os.path.join(F.DATA_DIR, endpoint, agent, f"zone_{zone}"),
           "--init-adapter", init_adapter, "--out", out, "--mu", str(mu),
           "--epochs", str(0.02 if smoke else lc["epochs_per_round"]),
           "--batch", str(lc["batch"]), "--grad-accum", str(lc["grad_accum"]),
           "--max-len", str(lc["max_len"]), "--lr", str(round_lr(lc, rnd)),
           "--r", str(tl["r"]), "--alpha", str(tl["alpha"]), "--dropout", str(tl["dropout"])]
    sh(cmd, log)


def aggregate(zone_dirs, weights, template, out, log):
    cmd = [_PY, os.path.join(_HERE, "aggregate_lora.py"), "--template", template, "--out", out]
    for d, w in zip(zone_dirs, weights):
        cmd += ["--zone", f"{d}:{int(w)}"]
    sh(cmd, log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(_HERE, "fl_config.json"))
    ap.add_argument("--endpoint", required=True, choices=["H0", "Hmax"])
    ap.add_argument("--condition", required=True, choices=["llm_fl", "local"])
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--exp-id", default="")
    ap.add_argument("--rounds", type=int, default=0, help="override max_rounds")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--smoke", action="store_true", help="tiny end-to-end sanity run")
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    base = cfg["base_model"]
    lora = cfg["lora"]
    tl = {**lora}                                    # r/alpha/dropout/target_modules
    lc = cfg["local_train"]
    mu = cfg["fedprox"]["mu"]
    fed = cfg["federation"]
    n_zones = fed["n_zones"]
    max_rounds = args.rounds or fed["max_rounds"]
    if args.smoke:
        max_rounds = 1
        cfg["eval"]["val_limit"] = 60
    conv_w, conv_tol = fed["conv_window"], fed["conv_tol"]

    exp_id = args.exp_id or f"{args.endpoint}_{args.condition}_seed{args.seed}"
    exp = os.path.join(F.RUNS_DIR, exp_id)
    os.makedirs(exp, exist_ok=True)
    log = os.path.join(exp, "run.log")
    print(f"=== experiment {exp_id}  rounds<= {max_rounds}  mu={mu} ===")

    zman = zone_manifest(args.endpoint)
    Dr = {m["zone"]: m["n_rows"] for m in zman["zones"]}     # |D_r| for Eq 3.32

    # evaluate_round imported late (loads torch)
    import evaluate_round as EV
    import torch as _torch

    # ---- round 0: shared fresh init ----------------------------------------
    init_dir = ensure_init(base, lora, args.seed, log, args)
    r0 = os.path.join(exp, "round_000")
    history = []

    def eval_triple(adapters, split="val", cache=None):
        """Evaluate a 3-agent adapter set. With --resume, a round whose
        metrics.json already exists is read back instead of re-generating it
        (generation is the expensive half of a round)."""
        if args.resume and cache and os.path.exists(cache):
            m = json.load(open(cache))
            if "mcc_macro" in m:
                print(f"  [resume] reusing cached metrics {os.path.relpath(cache, exp)}")
                return m
        m, tm = EV.evaluate_global(adapters, cfg, split=split)
        del tm                                     # drop (tok, model); free VRAM
        if _torch.cuda.is_available():
            _torch.cuda.empty_cache()
        return m

    if args.condition == "llm_fl":
        gdir = {a: os.path.join(r0, "global", a) for a in A.AGENT_ORDER}
        for a in A.AGENT_ORDER:
            if not os.path.exists(os.path.join(gdir[a], "adapter_model.safetensors")):
                os.makedirs(os.path.dirname(gdir[a]), exist_ok=True)
                shutil.copytree(os.path.join(init_dir, a), gdir[a], dirs_exist_ok=True)
        m0 = eval_triple(gdir, cache=os.path.join(r0, "metrics.json"))
        history.append({"round": 0, "mcc_macro": m0["mcc_macro"], "metrics": m0})
        json.dump(m0, open(os.path.join(r0, "metrics.json"), "w"), indent=2)
        print(f"  round 0 (init) mcc_macro={m0['mcc_macro']} binary_mcc={m0['binary_mcc']}")

        for rnd in range(1, max_rounds + 1):
            rd = os.path.join(exp, f"round_{rnd:03d}")
            new_global = {}
            local_dirs_all = []
            for a in A.AGENT_ORDER:
                zdirs, weights = [], []
                for z in range(1, n_zones + 1):
                    out = os.path.join(rd, "local", f"zone_{z}", a)
                    if not (args.resume and os.path.exists(os.path.join(out, "adapter_model.safetensors"))):
                        train_zone(base, args.endpoint, z, a, gdir[a], out, mu, lc, tl, log, args.smoke, rnd)
                    zdirs.append(out)
                    weights.append(Dr[z])
                    local_dirs_all.append(out)
                gout = os.path.join(rd, "global", a)
                aggregate(zdirs, weights, zdirs[0], gout, log)
                new_global[a] = gout
            gdir = new_global
            m = eval_triple(gdir, cache=os.path.join(rd, "metrics.json"))
            history.append({"round": rnd, "mcc_macro": m["mcc_macro"], "metrics": m})
            json.dump(m, open(os.path.join(rd, "metrics.json"), "w"), indent=2)

            # overhead (analytical + measured) for this round
            import overhead as OV
            comm = {"analytical_eq_3_71": OV.analytical(gdir["a1"]),
                    "measured": OV.measured(local_dirs_all,
                                            [gdir[a] for a in A.AGENT_ORDER], n_zones)}
            json.dump(comm, open(os.path.join(rd, "communication.json"), "w"), indent=2)
            print(f"  round {rnd} mcc_macro={m['mcc_macro']} binary_mcc={m['binary_mcc']} "
                  f"fpr={m['fpr']} rc={m['rc_mean']}")

            curve = [h["mcc_macro"] for h in history]
            kc = kappa_conv(curve, conv_w, conv_tol)
            if kc is not None:
                print(f"  Eq 3.73 converged: kappa_conv = round {kc}")
                break

    else:  # local-only: per-zone adapter chains, no aggregation
        # each zone's per-agent current adapter starts at the shared init
        zcur = {z: {a: os.path.join(init_dir, a) for a in A.AGENT_ORDER}
                for z in range(1, n_zones + 1)}
        # round 0 eval (all zones identical -> evaluate once, replicate)
        m0 = eval_triple({a: os.path.join(init_dir, a) for a in A.AGENT_ORDER})
        per_zone_curves = {z: [m0["mcc_macro"]] for z in range(1, n_zones + 1)}
        history.append({"round": 0, "zone_mcc_macro": {z: m0["mcc_macro"] for z in zcur},
                        "summary_mcc_macro": m0["mcc_macro"]})
        os.makedirs(r0, exist_ok=True)
        json.dump({"round0_shared_init": m0}, open(os.path.join(r0, "metrics.json"), "w"), indent=2)
        print(f"  round 0 (init) mcc_macro={m0['mcc_macro']}")

        for rnd in range(1, max_rounds + 1):
            rd = os.path.join(exp, f"round_{rnd:03d}")
            zone_m = {}
            for z in range(1, n_zones + 1):
                newz = {}
                for a in A.AGENT_ORDER:
                    out = os.path.join(rd, "local", f"zone_{z}", a)
                    if not (args.resume and os.path.exists(os.path.join(out, "adapter_model.safetensors"))):
                        train_zone(base, args.endpoint, z, a, zcur[z][a], out, mu, lc, tl, log, args.smoke, rnd)
                    newz[a] = out
                zcur[z] = newz
                mz = eval_triple(newz, cache=os.path.join(rd, "local", f"zone_{z}", "metrics.json"))
                zone_m[z] = mz["mcc_macro"]
                per_zone_curves[z].append(mz["mcc_macro"])
                json.dump(mz, open(os.path.join(rd, "local", f"zone_{z}", "metrics.json"), "w"), indent=2)
            summary = round(sum(zone_m.values()) / len(zone_m), 4)
            history.append({"round": rnd, "zone_mcc_macro": zone_m, "summary_mcc_macro": summary})
            print(f"  round {rnd} per-zone mcc_macro={zone_m} summary={summary}")

            curve = [h["summary_mcc_macro"] for h in history]
            kc = kappa_conv(curve, conv_w, conv_tol)
            if kc is not None:
                print(f"  Eq 3.73 (summary curve) converged: kappa_conv = round {kc}")
                break

    # ---- finalize history + kappa_conv -------------------------------------
    if args.condition == "llm_fl":
        curve = [h["mcc_macro"] for h in history]
    else:
        curve = [h["summary_mcc_macro"] for h in history]
    kc = kappa_conv(curve, conv_w, conv_tol)
    out = {
        "exp_id": exp_id, "endpoint": args.endpoint, "condition": args.condition,
        "seed": args.seed, "mu": mu, "rounds_run": len(history) - 1,
        "max_rounds": max_rounds, "conv_window": conv_w, "conv_tol": conv_tol,
        "mcc_macro_curve": curve,
        "kappa_conv": kc,
        "kappa_conv_note": (f"converged at round {kc}" if kc is not None
                            else f"not converged by round {len(history)-1}"),
        "final_mcc_macro": curve[-1],
        "history": history,
    }
    if args.condition == "local":
        out["per_zone_curves"] = per_zone_curves
        out["per_zone_kappa_conv"] = {z: kappa_conv(c, conv_w, conv_tol)
                                      for z, c in per_zone_curves.items()}
    json.dump(out, open(os.path.join(exp, "history.json"), "w"), indent=2)
    print(f"=== done {exp_id}: {out['kappa_conv_note']}, final mcc_macro={curve[-1]} ===")
    print(f"    history -> {os.path.join(exp, 'history.json')}")


if __name__ == "__main__":
    main()
