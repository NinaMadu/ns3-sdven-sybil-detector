"""
Stage-2 LLM sensitivity analysis (Table 4.9) — cheap, honest, resumable.

WHAT THIS IS
------------
A one-factor-at-a-time (OFAT) sweep of the 10 Table-4.9 hyperparameters around
the frozen Stage-2 recipe, scored jointly on DETECTION QUALITY and DEPLOYMENT
COST (latency / VRAM / adapter size) — the accuracy-vs-edge-memory-vs-response-
time trade-off.

TARGET = THE DEPLOYED DETECTOR
------------------------------
Base and adapters default to exactly what the live real-time detector runs, per
`consensus_config.json` + `consensus_infer.py:FROZEN_DEFAULTS`:

    Qwen/Qwen2.5-1.5B-Instruct  +  adapters/qwen1_5b_a{1,2,3}
    omega uniform 1/3,  theta_consensus 0.6667,  max_new 128

so every number this sweep produces speaks about the system actually in service,
not about a bake-off comparator.

It is made cheap by three disclosable devices, NOT by cutting corners:

  A. Train-set subsample (default 10k of 45,239). The corpus is heavily
     oversaturated for this task (deployed Qwen agents sit at binary MCC
     0.9994 / 1.0000 / 0.9997), so relative sensitivity ordering survives
     subsampling. ~4.5x cheaper.
  B. One representative agent (default a2). On the deployed Qwen base NO agent
     has accuracy headroom, so the agent is chosen on the axis that does carry
     signal: a2 is the LATENCY BOTTLENECK at 6.61 windows/s (vs a1 9.49, a3
     7.43). All three agents run per window, so a2 gates consensus response
     time — tuning the bottleneck is what moves deployment cost.
  C. Val subsample (default 2k of 7,246) for sweep scoring. The full 7,938-row
     TEST set is never touched by the sweep — it is reserved for the Phase-3
     confirmation run only.

EXPECT A FLAT ACCURACY COLUMN
-----------------------------
On the deployed Qwen agents every per-class recall is 1.000 except outsider
(0.9925-0.9975) and sim (0.9948-0.999), and json_valid_rate is 1.000 for all
three. The honest expected finding is therefore "detection quality is
insensitive across the entire grid; deployment cost is not". That is a real
result and it is the one that justifies the edge-deployment argument — but it
only reads as a result if the cost columns are reported beside the metric.
A flat accuracy column is embarrassing only when it is the only column.

Every one of those is reported in the emitted scorecard so the write-up can
state it plainly. See `disclosure_sentence` in sweep_summary.json.

WHY A NOISE FLOOR COMES FIRST
-----------------------------
The existing runs are single-seed (`fl_config.json`: "seeds": [42]). Without a
repeat-seed baseline you cannot tell a real effect from run-to-run jitter, and
every row of the table is unfalsifiable. Phase 0 trains the baseline config at
N seeds and reports sigma. The selection rule then only accepts a configuration
as "different" if it moves the metric by more than 2*sigma.

CEILING EFFECT
--------------
Binary MCC is saturated. The primary sweep metric is therefore 6-class macro-F1
EXCLUDING `malicious_controller`, whose recall is a structural 0.000 in every
scorecard (no vehicle-tier windows exist for class 6) and which would otherwise
move the metric for reasons unrelated to any hyperparameter.

PHASES
------
  0  noise floor        baseline x N seeds                       ~1.0 h
  1  eval-only          max reasoning tokens {32,64,128}         ~0.3 h
  2  OFAT               8 train-time parameters, 15 arms         ~5.0 h
  3  confirmation       winner retrained on FULL corpus, TEST    ~6.1 h
  4  FedProx mu         Stage-3 federation, reduced rounds      ~10.5 h

Phases 0-3 ~= 16 h on the RTX 5090 (one overnight) on the deployed Qwen-1.5B
base. Phase 4 is Stage-3 and is emitted as ready-to-run configs + commands
rather than executed inline. Run `--dry-run` for the exact per-arm estimate.

SHARED GPU
----------
An `llm_sidecar serve` daemon holds ~15.8 GB of the 32 GB card. Qwen-1.5B has a
151k vocab, so the training logits tensor is large and per-device batch 8 at
length 1024 will OOM against that. The trainer therefore backs off
automatically: on CUDA OOM it halves the per-device batch and doubles
gradient accumulation, which leaves the EFFECTIVE batch — the thing the sweep
is actually varying — unchanged, so runs stay comparable. Use
--per-device-batch to set the starting point.

USAGE
-----
    ML=.../ns-3.35/sybil-attack/ml
    $ML/.venv/bin/python llm_sensitivity.py --dry-run          # plan + estimate
    $ML/.venv/bin/python llm_sensitivity.py --phase 0
    $ML/.venv/bin/python llm_sensitivity.py --phase 2
    $ML/.venv/bin/python llm_sensitivity.py --phase all        # 0,1,2 then 3
    $ML/.venv/bin/python llm_sensitivity.py --report           # rebuild tables

Resumable: every completed config is appended to sweep/results.jsonl and skipped
on re-run. Safe to kill and restart. Run under tmux (multi-hour).

NOTE: the 4-bit / 8-bit arms need `bitsandbytes`, which is NOT currently in
ml/.venv. Without it those two arms are SKIPPED (recorded as skipped, not
silently dropped). Install with:  ml/.venv/bin/pip install bitsandbytes
"""

import argparse
import gc
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import time

import numpy as np

# Must precede the torch import. The sweep shares the GPU with a long-lived
# serving daemon, and expandable segments avoid fragmentation-induced OOM.
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
import torch  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "common"))
sys.path.insert(0, _HERE)

import constants as C          # noqa: E402
import agents as A             # noqa: E402
import consensus_infer as I    # noqa: E402
from eval_fusion import dir_size_mb  # noqa: E402

# ---------------------------------------------------------------------------
# Frozen Stage-2 recipe = the OFAT centre point (train_lora_generic.py defaults)
# ---------------------------------------------------------------------------
ALL_PROJ = ["q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"]
QV_PROJ = ["q_proj", "v_proj"]

BASELINE = {
    "r": 8,               # alpha follows the paper's alpha = 2r convention
    "dropout": 0.05,
    "target": "all",      # all | qv
    "lr": 2e-4,
    "eff_batch": 16,      # per-device 8 x grad-accum 2
    "epochs": 2,
    "max_len": 1024,
    "quant": "bf16",      # bf16 | nf4 | int8
    "max_new": 128,       # eval-only (max reasoning tokens)
}

# OFAT arms: parameter -> non-baseline candidate values (Table 4.9 candidate sets
# minus the centre point, which Phase 0 already trains).
OFAT_ARMS = {
    "r":        [4, 16],
    "quant":    ["nf4", "int8"],
    "target":   ["qv"],
    "dropout":  [0.0, 0.1],
    "lr":       [1e-4, 5e-4],
    "eff_batch": [8, 32],
    "epochs":   [1, 3],
    "max_len":  [256, 512],
}
EVAL_ONLY_ARMS = {"max_new": [32, 64]}     # no retraining required
FEDPROX_MU_ARMS = [0.001, 0.1]             # Stage-3, phase 4

# Metric classes: drop the structurally-empty class 6 (see module docstring).
EXCLUDED_CLASS = "malicious_controller"
METRIC_CLASSES = [c for c in C.ATTACK_CLASSES if c != EXCLUDED_CLASS]

# Measured cost constants, from adapters/*/train_meta.json + scorecards/*.json
# on the RTX 5090. Used only for --dry-run estimation.
SEC_PER_EXAMPLE_EPOCH = 4749.6 / (45239 * 2)      # llama1b @ len1024 => 0.0525 s
BASE_COST = {"meta-llama/Llama-3.2-1B-Instruct": 1.00,   # 4749.6 s reference
             "Qwen/Qwen2.5-1.5B-Instruct": 1.55,          # 7358.5 s
             "google/gemma-2-2b-it": 2.63}                # 12509.2 s
QUANT_COST = {"bf16": 1.0, "nf4": 1.4, "int8": 1.5}
TARGET_COST = {"all": 1.0, "qv": 0.85}
EVAL_WIN_PER_S = 10.0        # conservative; measured 6.61-15.45 across agents


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def cfg_id(cfg):
    """Short deterministic id: 'baseline', 'seed43', 'r4', 'quant-nf4', ..."""
    diffs = [f"{k}-{cfg[k]}" for k in sorted(BASELINE) if cfg[k] != BASELINE[k]]
    seed = cfg.get("seed", 42)
    if not diffs:
        return "baseline" if seed == 42 else f"baseline_seed{seed}"
    return "_".join(d.replace("_", "") for d in diffs)


def make_cfg(**over):
    cfg = dict(BASELINE)
    cfg["seed"] = 42
    cfg.update(over)
    return cfg


def label_of(row):
    """Ground-truth attack_type from the assistant turn of a chat record."""
    try:
        return json.loads(row["messages"][-1]["content"]).get("attack_type", "legitimate")
    except Exception:
        return "legitimate"


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f]


def stratified_subsample(rows, n, seed=42):
    """Class-proportional subsample. Preserves the real distribution, which is
    what makes the sweep's relative ordering transferable to the full corpus."""
    if not n or n >= len(rows):
        return rows
    by = {}
    for r in rows:
        by.setdefault(label_of(r), []).append(r)
    rng = random.Random(seed)
    out, frac = [], n / len(rows)
    for lab in sorted(by):
        pool = by[lab]
        rng.shuffle(pool)
        take = max(1, int(round(len(pool) * frac)))
        out.extend(pool[:take])
    rng.shuffle(out)
    return out[:n]


def build_data_cache(sweep_dir, agent, train_n, val_n, data_seed=42):
    """One fixed subsample reused by every config, so only the hyperparameter
    varies between runs (the data is never re-drawn)."""
    dst = os.path.join(sweep_dir, "data_cache", f"{agent}_t{train_n}_v{val_n}")
    if os.path.exists(os.path.join(dst, "val.jsonl")):
        return dst
    os.makedirs(dst, exist_ok=True)
    src = os.path.join(_HERE, f"data_{agent}")
    for split, n in (("train", train_n), ("val", val_n)):
        rows = read_jsonl(os.path.join(src, f"{split}.jsonl"))
        sub = stratified_subsample(rows, n, data_seed)
        with open(os.path.join(dst, f"{split}.jsonl"), "w") as f:
            for r in sub:
                f.write(json.dumps(r) + "\n")
        print(f"    data_cache {split}: {len(rows)} -> {len(sub)}")
    return dst


def free_gpu():
    """Drop Python-side references and return cached blocks to the driver.

    gc.collect() matters: PyTorch frees a tensor's device memory only when the
    last Python reference dies, and reference cycles (trainer <-> model) survive
    a bare `del` until the collector runs.
    """
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def free_vram_gb():
    if not torch.cuda.is_available():
        return None
    free, _ = torch.cuda.mem_get_info()
    return free / 1e9


def quant_config(quant):
    """BitsAndBytesConfig for nf4 / int8, or None for bf16. Returns (cfg, err)."""
    if quant == "bf16":
        return None, None
    try:
        import bitsandbytes  # noqa: F401
        from transformers import BitsAndBytesConfig
    except Exception as e:
        return None, f"bitsandbytes unavailable ({e.__class__.__name__}: {e})"
    if quant == "nf4":
        return BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                  bnb_4bit_use_double_quant=True,
                                  bnb_4bit_compute_dtype=torch.bfloat16), None
    if quant == "int8":
        return BitsAndBytesConfig(load_in_8bit=True), None
    return None, f"unknown quant {quant}"


# ---------------------------------------------------------------------------
# train
# ---------------------------------------------------------------------------
def train_one(cfg, base, data_dir, out_dir, per_dev_start=8):
    """LoRA fine-tune under `cfg`. Mirrors train_lora_generic.py exactly except
    that every Table-4.9 knob is parameterised. Returns meta dict.

    On CUDA OOM (the card is shared with a serving daemon) the per-device batch
    is halved and gradient accumulation doubled, preserving the EFFECTIVE batch
    so the run remains comparable to every other arm.
    """
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    qcfg, qerr = quant_config(cfg["quant"])
    if qerr:
        return {"skipped": qerr}

    ds = load_dataset("json", data_files={
        "train": os.path.join(data_dir, "train.jsonl"),
        "val":   os.path.join(data_dir, "val.jsonl")})

    # Effective batch is the swept quantity; it is realised as
    # per_device x grad_accum. Memory is governed by per_device alone, so the
    # backoff below can trade one for the other without changing the arm.
    eff = cfg["eff_batch"]
    per_dev = min(per_dev_start, eff)
    attempts = []
    while per_dev >= 1:
        attempts.append(per_dev)
        per_dev //= 2

    last_err = None
    for per_dev in attempts:
        grad_accum = max(1, eff // per_dev)
        model = trainer = None
        try:
            free_gpu()
            tok = AutoTokenizer.from_pretrained(base)
            if tok.pad_token is None:
                tok.pad_token = tok.eos_token

            kw = dict(dtype=torch.bfloat16, device_map={"": 0})
            if qcfg is not None:
                kw["quantization_config"] = qcfg
            model = AutoModelForCausalLM.from_pretrained(base, **kw)
            model.config.use_cache = False
            if qcfg is not None:
                from peft import prepare_model_for_kbit_training
                model = prepare_model_for_kbit_training(
                    model, use_gradient_checkpointing=True)

            lora = LoraConfig(
                r=cfg["r"], lora_alpha=2 * cfg["r"],  # paper convention alpha=2r
                lora_dropout=cfg["dropout"], bias="none", task_type="CAUSAL_LM",
                target_modules=(ALL_PROJ if cfg["target"] == "all" else QV_PROJ))

            sft = SFTConfig(
                output_dir=out_dir, num_train_epochs=cfg["epochs"],
                per_device_train_batch_size=per_dev,
                gradient_accumulation_steps=grad_accum,
                learning_rate=cfg["lr"], lr_scheduler_type="cosine",
                warmup_ratio=0.03, bf16=True, gradient_checkpointing=True,
                logging_steps=50, eval_strategy="no", save_strategy="no",
                max_length=cfg["max_len"], packing=False, report_to="none",
                seed=cfg["seed"], data_seed=cfg["seed"])

            if torch.cuda.is_available():
                torch.cuda.reset_peak_memory_stats()
            t0 = time.time()
            trainer = SFTTrainer(model=model, args=sft, train_dataset=ds["train"],
                                 peft_config=lora, processing_class=tok)
            trainer.train()
            wall = time.time() - t0
            peak = (torch.cuda.max_memory_allocated() / 1e9
                    if torch.cuda.is_available() else None)
            trainer.save_model(out_dir)
            tok.save_pretrained(out_dir)

            meta = {"base": base, "train_wall_s": round(wall, 1),
                    "train_peak_vram_gb": round(peak, 2) if peak else None,
                    "per_device_batch": per_dev, "grad_accum": grad_accum,
                    "effective_batch": per_dev * grad_accum,
                    "oom_backoff": per_dev != min(per_dev_start, eff),
                    "n_train": len(ds["train"]), **{k: cfg[k] for k in BASELINE},
                    "seed": cfg["seed"], "lora_alpha": 2 * cfg["r"]}
            json.dump(meta, open(os.path.join(out_dir, "train_meta.json"), "w"),
                      indent=2)
            del trainer, model
            free_gpu()
            return meta

        except torch.OutOfMemoryError as e:
            # str(), NOT the exception object: holding `e` keeps its traceback
            # alive, which pins every frame local -- including the model -- and
            # leaks ~3 GB per retry, defeating the backoff entirely.
            last_err = str(e).split("\n")[0]
            print(f"  OOM at per_device_batch={per_dev}; halving "
                  f"(effective batch {eff} preserved, so the arm is unchanged)")
            del trainer, model
            free_gpu()
            continue

    return {"skipped": f"OOM even at per_device_batch=1 ({last_err})"}


# ---------------------------------------------------------------------------
# evaluate (single agent — consensus is a Phase-3 concern)
# ---------------------------------------------------------------------------
def load_single_agent(base, adapter, quant="bf16"):
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    qcfg, qerr = quant_config(quant)
    if qerr:
        raise RuntimeError(qerr)
    tok = AutoTokenizer.from_pretrained(adapter)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"          # required for batched generation

    kw = dict(dtype=torch.bfloat16, device_map={"": 0})
    if qcfg is not None:
        kw["quantization_config"] = qcfg
    model = AutoModelForCausalLM.from_pretrained(base, **kw)
    model = PeftModel.from_pretrained(model, adapter)
    model.eval()
    return tok, model


def eval_one(base, adapter, rows, batch, max_new, quant="bf16"):
    """Generate + score one agent. Returns the metric dict."""
    from sklearn.metrics import f1_score, matthews_corrcoef, recall_score

    tok, model = load_single_agent(base, adapter, quant)
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()

    gold = [json.loads(r["messages"][-1]["content"]) for r in rows]
    preds, dt, ntok = I.agent_generate(
        model, tok, [r["messages"][:-1] for r in rows], batch, max_new)

    infer_peak = torch.cuda.max_memory_allocated() / 1e9 if torch.cuda.is_available() else None

    y_bin = [1 if g["verdict"] == "sybil" else 0 for g in gold]
    y_mc = [g.get("attack_type", "legitimate") for g in gold]
    d, p_mc = [], []
    for p in preds:
        if p is None:
            d.append(0)
            p_mc.append("legitimate")
            continue
        at = p.get("attack_type")
        d.append(1 if p.get("verdict") == "sybil" else 0)
        p_mc.append(at if at in C.ATTACK_CLASSES else "legitimate")

    fp = sum(1 for t, q in zip(y_bin, d) if t == 0 and q == 1)
    nneg = sum(1 for t in y_bin if t == 0)

    del model
    free_gpu()

    return {
        "n_eval": len(rows),
        # PRIMARY metric — 6 classes, class 6 excluded (structurally empty)
        "macro_f1_6cls": round(float(f1_score(y_mc, p_mc, labels=METRIC_CLASSES,
                                              average="macro", zero_division=0)), 4),
        "multiclass_mcc": round(float(matthews_corrcoef(y_mc, p_mc)), 4),
        "binary_mcc": round(float(matthews_corrcoef(y_bin, d)), 4),
        "false_positive_rate": round(fp / nneg, 4) if nneg else None,
        "json_valid_rate": round(float(np.mean([p is not None for p in preds])), 4),
        "per_class_recall": dict(zip(METRIC_CLASSES, recall_score(
            y_mc, p_mc, labels=METRIC_CLASSES, average=None,
            zero_division=0).round(4).tolist())),
        # DEPLOYMENT COST
        "throughput_windows_per_s": round(len(rows) / dt, 2) if dt else None,
        "tokens_per_s": round(ntok / dt, 1) if dt else None,
        "latency_ms_per_window": round(1000 * dt / len(rows), 1) if rows else None,
        "infer_peak_vram_gb": round(infer_peak, 2) if infer_peak else None,
        "adapter_size_mb": dir_size_mb(adapter),
    }


# ---------------------------------------------------------------------------
# results store
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, path):
        self.path = path
        self.rows = read_jsonl(path) if os.path.exists(path) else []

    def done(self, rid):
        return any(r["id"] == rid for r in self.rows)

    def add(self, rec):
        self.rows.append(rec)
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def get(self, rid):
        return next((r for r in self.rows if r["id"] == rid), None)


def run_config(cfg, args, store, data_dir, val_rows, phase, keep_adapter=False):
    """Train (unless eval-only) + evaluate one config, with resume."""
    rid = f"p{phase}:{cfg_id(cfg)}"
    if store.done(rid):
        print(f"  [skip] {rid} (already in results.jsonl)")
        return store.get(rid)

    print(f"\n=== {rid} ===")
    print("  " + json.dumps({k: cfg[k] for k in sorted(BASELINE)}))
    out_dir = os.path.join(args.out, "adapters", cfg_id(cfg))
    rec = {"id": rid, "phase": phase, "config": {k: cfg[k] for k in sorted(BASELINE)},
           "seed": cfg["seed"], "agent": args.agent, "base": args.base,
           "ts": time.strftime("%Y-%m-%d %H:%M:%S")}

    t0 = time.time()
    meta = train_one(cfg, args.base, data_dir, out_dir, args.per_device_batch)
    if meta.get("skipped"):
        rec["status"] = "skipped"
        rec["reason"] = meta["skipped"]
        print(f"  SKIPPED: {meta['skipped']}")
        store.add(rec)
        return rec
    rec.update({k: meta[k] for k in
                ("train_wall_s", "train_peak_vram_gb", "n_train",
                 "per_device_batch", "grad_accum", "effective_batch",
                 "oom_backoff", "lora_alpha")})

    try:
        rec.update(eval_one(args.base, out_dir, val_rows, args.gen_batch,
                            cfg["max_new"], cfg["quant"]))
        rec["status"] = "ok"
    except Exception as e:                                   # keep the sweep alive
        rec["status"] = "eval_failed"
        rec["reason"] = f"{e.__class__.__name__}: {str(e).splitlines()[0]}"
        print(f"  EVAL FAILED: {rec['reason']}")
        free_gpu()

    rec["total_wall_s"] = round(time.time() - t0, 1)
    store.add(rec)
    if not keep_adapter and not args.keep_adapters:
        shutil.rmtree(out_dir, ignore_errors=True)           # adapters are ~200-300 MB each
        rec_note = " (adapter deleted; --keep-adapters to retain)"
    else:
        rec_note = ""
    print(f"  -> macro_f1_6cls={rec.get('macro_f1_6cls')} "
          f"binary_mcc={rec.get('binary_mcc')} "
          f"lat={rec.get('latency_ms_per_window')}ms "
          f"vram={rec.get('infer_peak_vram_gb')}GB "
          f"[{rec['total_wall_s']/60:.1f} min]{rec_note}")
    return rec


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------
def phase0(args, store, data_dir, val_rows):
    """Noise floor: baseline at N seeds. Everything else is judged against this."""
    print("\n" + "=" * 72)
    print("PHASE 0 — noise floor (baseline x %d seeds)" % len(args.seeds))
    print("=" * 72)
    for s in args.seeds:
        run_config(make_cfg(seed=s), args, store, data_dir, val_rows, phase=0)


def phase1(args, store, val_rows):
    """Eval-only: max reasoning tokens. No training — reuses an EXISTING full
    adapter, so this is minutes, not hours."""
    print("\n" + "=" * 72)
    print("PHASE 1 — max reasoning tokens (eval-only, existing adapter)")
    print("=" * 72)
    adapter = args.eval_only_adapter
    if not os.path.isdir(adapter):
        print(f"  !! adapter not found: {adapter}\n     pass --eval-only-adapter")
        return
    for mn in EVAL_ONLY_ARMS["max_new"] + [BASELINE["max_new"]]:
        rid = f"p1:max_new-{mn}"
        if store.done(rid):
            print(f"  [skip] {rid}")
            continue
        print(f"\n=== {rid} ===")
        t0 = time.time()
        rec = {"id": rid, "phase": 1, "config": {**BASELINE, "max_new": mn},
               "seed": 42, "agent": args.agent, "base": args.base,
               "adapter": adapter, "eval_only": True,
               "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            rec.update(eval_one(args.base, adapter, val_rows, args.gen_batch, mn))
            rec["status"] = "ok"
        except Exception as e:
            rec["status"] = "eval_failed"
            rec["reason"] = f"{e.__class__.__name__}: {e}"
            print(f"  EVAL FAILED: {rec['reason']}")
        rec["total_wall_s"] = round(time.time() - t0, 1)
        store.add(rec)
        print(f"  -> macro_f1_6cls={rec.get('macro_f1_6cls')} "
              f"lat={rec.get('latency_ms_per_window')}ms")


def phase2(args, store, data_dir, val_rows):
    """OFAT over the 8 train-time parameters."""
    print("\n" + "=" * 72)
    print("PHASE 2 — OFAT, 8 train-time parameters")
    print("=" * 72)
    for param, values in OFAT_ARMS.items():
        if args.only and param not in args.only:
            continue
        for v in values:
            run_config(make_cfg(**{param: v}), args, store, data_dir, val_rows, phase=2)


def phase3(args, store):
    """Confirmation: retrain the selected config on the FULL corpus, all three
    agents, then hand off to consensus_eval.py for the full TEST-set number."""
    print("\n" + "=" * 72)
    print("PHASE 3 — confirmation on full corpus (all agents, full test set)")
    print("=" * 72)
    sel = select(store, args)
    if not sel:
        print("  no completed runs to select from — run phases 0/2 first")
        return
    win = sel["selected"]["config"]
    if sel["selected"]["id"].startswith("p0:baseline") and not args.force_confirm:
        print("  Winner IS the baseline — the frozen recipe already stands.")
        print("  Nothing to retrain. (--force-confirm to run anyway.)")
        return

    print(f"  winner: {sel['selected']['id']}  {json.dumps(win)}")
    adapters = []
    for agent in A.AGENT_ORDER:
        cfg = make_cfg(**{k: win[k] for k in BASELINE})
        out = os.path.join(args.out, "confirm", f"{args.base.split('/')[-1]}_{agent}")
        adapters.append(out)
        if os.path.exists(os.path.join(out, "adapter_config.json")):
            print(f"  [skip] {agent} already trained")
            continue
        print(f"\n--- confirming {agent} on FULL data_{agent} ---")
        train_one(cfg, args.base, os.path.join(_HERE, f"data_{agent}"), out,
                  args.per_device_batch)

    cmd = [sys.executable, os.path.join(_HERE, "consensus_eval.py"),
           "--base", args.base, "--adapters", *adapters,
           "--scorecards", os.path.join(args.out, "confirm", "scorecards"),
           "--preds", os.path.join(args.out, "confirm", "preds.parquet"),
           "--max-new", str(win["max_new"]), "--test-limit", "0"]
    print("\n--- full consensus eval on the held-out TEST set ---")
    print("  " + " ".join(cmd))
    subprocess.run(cmd, check=False)


def phase4(args):
    """FedProx mu — Stage-3. Emits ready-to-run configs + commands rather than
    executing inline, because a federation run is a different driver
    (run_federation.py) with its own resume semantics.

    Reduced-round justification: every completed Stage-3 experiment records
    "not converged by round 5" in runs/*/history.json, so a mu COMPARISON at
    fewer rounds is no weaker than at 5 — it compares trajectories, not
    converged endpoints. Measured round cost ~2 h 37 min.
    """
    print("\n" + "=" * 72)
    print("PHASE 4 — FedProx mu (Stage-3, reduced rounds)")
    print("=" * 72)
    s3 = os.path.normpath(os.path.join(_HERE, "..", "stage3_agents"))
    src = os.path.join(s3, "fl_config.json")
    if not os.path.exists(src):
        print(f"  !! {src} not found")
        return
    outdir = os.path.join(args.out, "phase4_mu_configs")
    os.makedirs(outdir, exist_ok=True)
    cmds = []
    for mu in FEDPROX_MU_ARMS:
        cfg = json.load(open(src))
        cfg["_note"] = (f"SENSITIVITY ARM: FedProx mu={mu} at reduced rounds "
                        f"({args.mu_rounds}). Identical to fl_config.json in "
                        f"every other respect. Generated by llm_sensitivity.py.")
        cfg["fedprox"]["mu"] = mu
        cfg["federation"]["max_rounds"] = args.mu_rounds
        p = os.path.join(outdir, f"fl_config_mu{mu}.json")
        json.dump(cfg, open(p, "w"), indent=2)
        # --endpoint / --condition / --exp-id are required by run_federation.py
        # (no defaults) -- the mu effect is Hmax-only by design (µ regularises
        # client drift, which only exists under heterogeneity; H0 is uninformative).
        exp_id = f"{args.mu_endpoint}_llm_fl_mu{mu}_seed{args.seed}"
        cmds.append(f"{sys.executable} {os.path.join(s3, 'run_federation.py')} "
                    f"--config {p} --endpoint {args.mu_endpoint} "
                    f"--condition llm_fl --seed {args.seed} --exp-id {exp_id}")
        print(f"  wrote {p}")
    sh = os.path.join(outdir, "run_mu_sweep.sh")
    with open(sh, "w") as f:
        f.write("#!/usr/bin/env bash\nset -euo pipefail\n"
                "# FedProx mu sensitivity arms. ~%.1f h each at %d rounds\n"
                "# (measured %.2f h/round from runs/*/round_* timestamps).\n\n"
                % (args.mu_rounds * 2.617, args.mu_rounds, 2.617))
        f.write("\n".join(cmds) + "\n")
    os.chmod(sh, 0o755)
    print(f"\n  driver: {sh}")
    print(f"  estimated {len(FEDPROX_MU_ARMS) * args.mu_rounds * 2.617:.1f} h total")
    print("  run it under tmux; baseline mu=0.01 already exists in runs/")


# ---------------------------------------------------------------------------
# selection + reporting
# ---------------------------------------------------------------------------
def select(store, args):
    """Apply the pre-registered selection rule.

        Pick the configuration with the LOWEST deployment cost whose primary
        metric is within `k` noise-SD of the best observed value.

    Declaring this before looking at results is what makes it an analysis rather
    than a post-hoc story.
    """
    ok = [r for r in store.rows if r.get("status") == "ok"
          and r.get("macro_f1_6cls") is not None and not r.get("eval_only")]
    if not ok:
        return None
    base_runs = [r for r in ok if r["phase"] == 0]
    vals = [r["macro_f1_6cls"] for r in base_runs]
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    best = max(r["macro_f1_6cls"] for r in ok)
    band = best - args.k_sd * sd

    def cost(r):
        return (r.get("adapter_size_mb") or 1e9,
                r.get("latency_ms_per_window") or 1e9,
                r.get("infer_peak_vram_gb") or 1e9)

    eligible = [r for r in ok if r["macro_f1_6cls"] >= band]
    winner = min(eligible, key=cost)
    return {
        "rule": (f"lowest deployment cost (adapter MB, then latency, then VRAM) "
                 f"among configs within {args.k_sd} noise-SD of the best "
                 f"macro_f1_6cls"),
        "primary_metric": "macro_f1_6cls",
        "noise_sd": round(sd, 5),
        "noise_seeds": [r["seed"] for r in base_runs],
        "noise_values": vals,
        "best_metric": best,
        "acceptance_band_min": round(band, 5),
        "n_eligible": len(eligible),
        "selected": winner,
    }


def report(store, args):
    sel = select(store, args)
    rows = [r for r in store.rows if r.get("status") == "ok"]
    if not rows:
        print("no completed runs yet")
        return

    cols = [("id", "Config"), ("macro_f1_6cls", "macroF1-6"),
            ("binary_mcc", "binMCC"), ("json_valid_rate", "JSON"),
            ("latency_ms_per_window", "lat ms"), ("tokens_per_s", "tok/s"),
            ("infer_peak_vram_gb", "VRAM GB"), ("adapter_size_mb", "adpt MB"),
            ("train_wall_s", "train s")]

    lines = ["| " + " | ".join(c[1] for c in cols) + " |",
             "|" + "|".join("---" for _ in cols) + "|"]
    for r in sorted(rows, key=lambda x: (x["phase"], x["id"])):
        lines.append("| " + " | ".join(
            str(r.get(c[0], "")) for c in cols) + " |")
    table = "\n".join(lines)

    skipped = [r for r in store.rows if r.get("status") != "ok"]
    md = [f"# Stage-2 LLM sensitivity analysis (Table 4.9)\n",
          f"- base model: `{args.base}`",
          f"- swept agent: **{args.agent}** ({A.AGENTS[args.agent]['name']})",
          f"- train subsample: {args.train_n} | val subsample: {args.val_n}",
          f"- primary metric: **macro-F1 over {len(METRIC_CLASSES)} classes**, "
          f"excluding `{EXCLUDED_CLASS}` (structurally empty at this tier)",
          ""]
    if sel:
        md += [f"## Noise floor\n",
               f"Baseline trained at seeds {sel['noise_seeds']}: "
               f"macro_f1_6cls = {sel['noise_values']}, **sigma = {sel['noise_sd']}**.",
               f"Differences smaller than {args.k_sd}*sigma = "
               f"{round(args.k_sd * sel['noise_sd'], 5)} are NOT interpretable.\n",
               f"## Selection\n", f"Rule (pre-registered): {sel['rule']}.\n",
               f"Best macro_f1_6cls {sel['best_metric']}; acceptance band "
               f">= {sel['acceptance_band_min']}; {sel['n_eligible']} configs eligible.\n",
               f"**Selected: `{sel['selected']['id']}`** — "
               f"`{json.dumps(sel['selected']['config'])}`\n"]
    md += ["## All runs\n", table, ""]
    if skipped:
        md += ["## Not run\n"]
        md += [f"- `{r['id']}`: {r.get('status')} — {r.get('reason','')}"
               for r in skipped]
        md += [""]

    disclosure = (
        f"The hyperparameter sweep was conducted on a {args.train_n:,}-sample "
        f"stratified subset of the training corpus and a {args.val_n:,}-window "
        f"validation subset for tractability, using agent {args.agent} as the "
        f"representative endpoint; the selected configuration was then retrained "
        f"on the full 45,239-sample corpus across all three agents and evaluated "
        f"on the held-out 7,938-window test set. Run-to-run variance was "
        f"estimated from {len(args.seeds)} seeds at the baseline configuration "
        f"(sigma = {sel['noise_sd'] if sel else 'TBD'}).")
    md += ["## Disclosure sentence for the methodology section\n",
           "> " + disclosure, ""]

    mdp = os.path.join(args.out, "SENSITIVITY_REPORT.md")
    with open(mdp, "w") as f:
        f.write("\n".join(md))

    summary = {"base": args.base, "agent": args.agent,
               "train_subsample": args.train_n, "val_subsample": args.val_n,
               "primary_metric": "macro_f1_6cls",
               "excluded_class": EXCLUDED_CLASS,
               "selection": sel, "disclosure_sentence": disclosure,
               "n_runs_ok": len(rows), "n_not_run": len(skipped)}
    json.dump(summary, open(os.path.join(args.out, "sweep_summary.json"), "w"),
              indent=2, default=str)

    # CSV for the thesis table
    import csv
    with open(os.path.join(args.out, "sensitivity_table.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([c[1] for c in cols])
        for r in sorted(rows, key=lambda x: (x["phase"], x["id"])):
            w.writerow([r.get(c[0], "") for c in cols])

    print("\n" + table)
    if sel:
        print(f"\nnoise sigma = {sel['noise_sd']}  |  selected = {sel['selected']['id']}")
    print(f"\nwrote {mdp}")
    print(f"wrote {os.path.join(args.out, 'sweep_summary.json')}")
    print(f"wrote {os.path.join(args.out, 'sensitivity_table.csv')}")


# ---------------------------------------------------------------------------
# dry-run estimator (measured constants, no GPU touched)
# ---------------------------------------------------------------------------
def estimate(cfg, args):
    n = args.train_n
    train = (SEC_PER_EXAMPLE_EPOCH * n * cfg["epochs"]
             * (cfg["max_len"] / 1024) * BASE_COST.get(args.base, 1.0)
             * QUANT_COST[cfg["quant"]] * TARGET_COST[cfg["target"]])
    ev = args.val_n / EVAL_WIN_PER_S * (cfg["max_new"] / 128) * BASE_COST.get(args.base, 1.0)
    return train + ev


def dry_run(args):
    print("=" * 72)
    print("DRY RUN — plan and cost estimate (measured constants, no GPU used)")
    print("=" * 72)
    print(f"base   : {args.base}")
    print(f"agent  : {args.agent}   train {args.train_n}  val {args.val_n}")
    print(f"seeds  : {args.seeds}\n")

    total = 0.0
    print(f"{'phase':<6} {'config':<24} {'est min':>8}")
    print("-" * 42)
    for s in args.seeds:
        c = make_cfg(seed=s)
        t = estimate(c, args)
        total += t
        print(f"{'0':<6} {cfg_id(c):<24} {t/60:>8.1f}")
    for mn in EVAL_ONLY_ARMS["max_new"] + [BASELINE["max_new"]]:
        t = args.val_n / EVAL_WIN_PER_S * (mn / 128) * BASE_COST.get(args.base, 1.0)
        total += t
        print(f"{'1':<6} {'max_new-' + str(mn):<24} {t/60:>8.1f}")
    for param, values in OFAT_ARMS.items():
        for v in values:
            c = make_cfg(**{param: v})
            t = estimate(c, args)
            total += t
            note = ""
            if param == "quant" and quant_config(v)[1]:
                note = "  (WILL SKIP: no bitsandbytes)"
                t = 0.0
            print(f"{'2':<6} {cfg_id(c):<24} {t/60:>8.1f}{note}")

    print("-" * 42)
    print(f"{'':<6} {'PHASES 0-2 TOTAL':<24} {total/60:>8.1f} min "
          f"= {total/3600:.1f} h")
    full = SEC_PER_EXAMPLE_EPOCH * 45239 * 2 * BASE_COST.get(args.base, 1.0)
    print(f"{'3':<6} {'confirm x3 agents':<24} {3*full/60:>8.1f} min "
          f"= {3*full/3600:.1f} h  (only if winner != baseline)")
    print(f"{'4':<6} {'fedprox mu (stage-3)':<24} "
          f"{len(FEDPROX_MU_ARMS)*args.mu_rounds*157:>8.1f} min "
          f"= {len(FEDPROX_MU_ARMS)*args.mu_rounds*2.617:.1f} h")
    print(f"\nGRAND TOTAL (0-3): {(total + 3*full)/3600:.1f} h")

    if quant_config("nf4")[1]:
        print("\n!! bitsandbytes is NOT installed — the nf4/int8 arms will be")
        print("   recorded as skipped. Install first if you want them:")
        print("   ml/.venv/bin/pip install bitsandbytes")
        print("   (this matters: 4-bit NF4 is the value your report currently")
        print("    names as SELECTED, and no adapter was ever trained with it.)")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Stage-2 LLM sensitivity analysis (Table 4.9)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phase", default="all",
                    help="0 | 1 | 2 | 3 | 4 | all  (all = 0,1,2 then 3)")
    ap.add_argument("--base", default=I.FROZEN_DEFAULTS["base_model"],
                    help="shared frozen base; defaults to the DEPLOYED detector "
                         "base from consensus_infer.FROZEN_DEFAULTS")
    ap.add_argument("--agent", default="a2", choices=A.AGENT_ORDER,
                    help="a2 = the latency bottleneck on the deployed Qwen base "
                         "(6.61 win/s vs a1 9.49, a3 7.43)")
    ap.add_argument("--per-device-batch", type=int, default=8,
                    help="starting per-device batch; halves automatically on OOM "
                         "with grad-accum compensating (effective batch preserved)")
    ap.add_argument("--train-n", type=int, default=10000, help="0 = full corpus")
    ap.add_argument("--val-n", type=int, default=2000, help="0 = full val")
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44],
                    help="noise-floor seeds (phase 0)")
    ap.add_argument("--gen-batch", type=int, default=16)
    ap.add_argument("--k-sd", type=float, default=2.0,
                    help="acceptance band in noise-SD for the selection rule")
    ap.add_argument("--only", nargs="*", default=None,
                    help="phase-2: restrict to these parameters")
    ap.add_argument("--eval-only-adapter", default=None,
                    help="phase-1 adapter; defaults to the DEPLOYED adapter for "
                         "--agent (consensus_infer.FROZEN_DEFAULTS)")
    ap.add_argument("--mu-rounds", type=int, default=2,
                    help="phase-4 federation rounds per mu arm")
    ap.add_argument("--mu-endpoint", default="Hmax", choices=["H0", "Hmax"],
                    help="phase-4 heterogeneity endpoint; Hmax by default since "
                         "FedProx's proximal term only has an effect to measure "
                         "under heterogeneity")
    ap.add_argument("--seed", type=int, default=42, help="phase-4 federation seed")
    ap.add_argument("--keep-adapters", action="store_true",
                    help="retain sweep adapters (~200-300 MB each, 15+ configs)")
    ap.add_argument("--force-confirm", action="store_true")
    ap.add_argument("--out", default=os.path.join(_HERE, "sensitivity"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", action="store_true", help="rebuild tables only")
    args = ap.parse_args()

    # Default phase-1 adapter = whatever the live detector actually loads.
    if args.eval_only_adapter is None:
        args.eval_only_adapter = I.load_config()["adapters"][args.agent]

    os.makedirs(args.out, exist_ok=True)
    if args.dry_run:
        dry_run(args)
        return

    store = Store(os.path.join(args.out, "results.jsonl"))
    if args.report:
        report(store, args)
        return

    phases = ["0", "1", "2", "3"] if args.phase == "all" else [args.phase]

    free = free_vram_gb()
    if free is not None:
        print(f"GPU free: {free:.1f} GB of "
              f"{torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB")
        if free < 8:
            print("  !! under 8 GB free — another process is holding the card.")
            print("     The trainer will back off per-device batch automatically,")
            print("     but expect slower runs. `nvidia-smi` to see what's there.")

    data_dir = val_rows = None
    if any(p in ("0", "1", "2") for p in phases):
        print("Preparing fixed subsample (drawn once, reused by every config) ...")
        data_dir = build_data_cache(args.out, args.agent, args.train_n, args.val_n)
        val_rows = read_jsonl(os.path.join(data_dir, "val.jsonl"))
        print(f"  train={args.train_n or 'full'}  val={len(val_rows)}")

    if "0" in phases:
        phase0(args, store, data_dir, val_rows)
    if "1" in phases:
        phase1(args, store, val_rows)
    if "2" in phases:
        phase2(args, store, data_dir, val_rows)
    if "3" in phases:
        phase3(args, store)
    if "4" in phases:
        phase4(args)
        return

    report(store, args)


if __name__ == "__main__":
    main()
