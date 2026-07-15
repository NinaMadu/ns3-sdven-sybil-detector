"""
Generalized fusion-head evaluation for the bake-off (6-class, any base model).

Extends ml/finetune/eval_model.py: parameterized base model + adapter, the
6-class taxonomy, and it additionally measures the bake-off's non-accuracy axes
(latency ms/window GPU single + batched, inference VRAM, tokens/sec, adapter
size, JSON-valid rate). Emits one scorecard JSON per candidate.

Run in the GPU env after train_lora_generic.py:
    python eval_fusion.py \
        --model Qwen/Qwen2.5-0.5B-Instruct \
        --adapter ml/fullmode/adapters/qwen0_5b \
        --data ml/fullmode/data/test.jsonl \
        --scorecard ml/fullmode/scorecards/qwen0_5b.json
"""

import argparse
import collections
import json
import os
import re
import time

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from constants import ATTACK_CLASSES as CLASSES


def extract_json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def dir_size_mb(path):
    total = 0
    for root, _, files in os.walk(path):
        for fn in files:
            total += os.path.getsize(os.path.join(root, fn))
    return round(total / 1e6, 1)


def load_rows(data_path, limit):
    rows = [json.loads(l) for l in open(data_path)]
    if limit and limit < len(rows):
        per = max(1, limit // len(CLASSES))
        buckets = collections.defaultdict(list)
        for r in rows:
            buckets[json.loads(r["messages"][-1]["content"])["attack_type"]].append(r)
        sub = []
        for c in CLASSES:
            sub.extend(buckets[c][:per])
        return sub
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--data", required=True, help="test.jsonl (chat format)")
    ap.add_argument("--scorecard", required=True, help="output scorecard JSON")
    ap.add_argument("--pred-out", default=None)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-new", type=int, default=256)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.adapter)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"

    base = AutoModelForCausalLM.from_pretrained(
        args.model, torch_dtype=torch.bfloat16, device_map={"": 0})
    model = PeftModel.from_pretrained(base, args.adapter)
    model.eval()

    rows = load_rows(args.data, args.limit)
    n = len(rows)
    print(f"Evaluating {args.model} on {n:,} examples (batch={args.batch}) ...")

    v_correct = t_correct = parse_fail = 0
    y_true, y_pred = [], []
    gen_tokens = 0
    batched_time = 0.0
    if args.pred_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.pred_out)), exist_ok=True)
    fout = open(args.pred_out, "w") if args.pred_out else None

    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()

    for start in range(0, n, args.batch):
        chunk = rows[start:start + args.batch]
        prompts = [tok.apply_chat_template(r["messages"][:-1],
                                           add_generation_prompt=True, tokenize=False)
                   for r in chunk]
        enc = tok(prompts, return_tensors="pt", padding=True).to(model.device)
        torch.cuda.synchronize() if torch.cuda.is_available() else None
        t0 = time.time()
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=args.max_new, do_sample=False,
                                 pad_token_id=tok.pad_token_id)
        torch.cuda.synchronize() if torch.cuda.is_available() else None
        batched_time += time.time() - t0

        gen = out[:, enc["input_ids"].shape[1]:]
        gen_tokens += int((gen != tok.pad_token_id).sum().item())
        texts = tok.batch_decode(gen, skip_special_tokens=True)

        for r, text in zip(chunk, texts):
            gold = json.loads(r["messages"][-1]["content"])
            pred = extract_json(text)
            if pred is None:
                parse_fail += 1
                pred_type = "PARSE_FAIL"
            else:
                pred_type = pred.get("attack_type", "PARSE_FAIL")
                if pred.get("verdict") == gold["verdict"]:
                    v_correct += 1
                if pred_type == gold["attack_type"]:
                    t_correct += 1
            y_true.append(gold["attack_type"])
            y_pred.append(pred_type if pred_type in CLASSES else "legitimate")
            if fout:
                fout.write(json.dumps({"true": gold, "pred_text": text}) + "\n")
        print(f"  {min(start + args.batch, n)}/{n} ...", flush=True)
    if fout:
        fout.close()

    # ---- single-window latency (batch=1, GPU) --------------------------------
    single_ms = None
    if n:
        one = tok.apply_chat_template(rows[0]["messages"][:-1],
                                      add_generation_prompt=True, tokenize=False)
        enc1 = tok([one], return_tensors="pt").to(model.device)
        for _ in range(2):  # warm-up
            with torch.no_grad():
                model.generate(**enc1, max_new_tokens=args.max_new, do_sample=False,
                               pad_token_id=tok.pad_token_id)
        torch.cuda.synchronize() if torch.cuda.is_available() else None
        t0 = time.time()
        with torch.no_grad():
            model.generate(**enc1, max_new_tokens=args.max_new, do_sample=False,
                           pad_token_id=tok.pad_token_id)
        torch.cuda.synchronize() if torch.cuda.is_available() else None
        single_ms = round((time.time() - t0) * 1000, 1)

    try:
        from sklearn.metrics import (classification_report, f1_score,
                                     matthews_corrcoef, recall_score)
        mcc = matthews_corrcoef(y_true, y_pred)
        macro_f1 = f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0)
        per_recall = dict(zip(CLASSES, recall_score(
            y_true, y_pred, labels=CLASSES, average=None, zero_division=0).round(4).tolist()))
        report = classification_report(y_true, y_pred, labels=CLASSES, zero_division=0)
    except ImportError:
        mcc = macro_f1 = None
        per_recall = {}
        report = "(sklearn missing)"

    # false-positive rate: legit windows the head wrongly flags as any Sybil type
    fp = fp_den = 0
    for yt, yp in zip(y_true, y_pred):
        if yt == "legitimate":
            fp_den += 1
            fp += (yp != "legitimate")
    fp_rate = round(fp / fp_den, 4) if fp_den else None

    peak_vram_gb = (round(torch.cuda.max_memory_allocated() / 1e9, 2)
                    if torch.cuda.is_available() else None)

    scorecard = {
        "model": args.model,
        "adapter": args.adapter,
        "n_eval": n,
        # performance
        "verdict_acc": round(v_correct / n, 4) if n else None,
        "attack_type_acc": round(t_correct / n, 4) if n else None,
        "mcc": round(mcc, 4) if mcc is not None else None,
        "macro_f1": round(macro_f1, 4) if macro_f1 is not None else None,
        "per_class_recall": per_recall,
        "false_positive_rate": fp_rate,
        "json_valid_rate": round(1 - parse_fail / n, 4) if n else None,
        # latency / compute
        "latency_ms_per_window_single": single_ms,
        "throughput_windows_per_s_batched": round(n / batched_time, 2) if batched_time else None,
        "tokens_per_s_batched": round(gen_tokens / batched_time, 1) if batched_time else None,
        "peak_inference_vram_gb": peak_vram_gb,
        "adapter_size_mb": dir_size_mb(args.adapter),
    }
    tmeta = os.path.join(args.adapter, "train_meta.json")
    if os.path.exists(tmeta):
        scorecard["finetune_wall_s"] = json.load(open(tmeta)).get("finetune_wall_s")

    os.makedirs(os.path.dirname(os.path.abspath(args.scorecard)), exist_ok=True)
    json.dump(scorecard, open(args.scorecard, "w"), indent=2)
    print("\n=== Scorecard ===")
    print(json.dumps(scorecard, indent=2))
    print(report)


if __name__ == "__main__":
    main()
