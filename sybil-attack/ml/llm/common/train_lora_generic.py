"""
Parameterized LoRA fine-tune for the full-mode fusion bake-off.

Identical recipe to ml/finetune/train_lora.py (r=16, alpha=32, 2 epochs, 2e-4
cosine, bf16, LoRA on all attn+MLP proj) — ONLY the base model and I/O paths are
arguments, so every candidate is trained the same way and the comparison
isolates the base LLM.

Run in the GPU env (smart-road-assistant/.venv, torch 2.12 / cu13):
    python train_lora_generic.py \
        --model Qwen/Qwen2.5-0.5B-Instruct \
        --data  ml/fullmode/data \
        --out   ml/fullmode/adapters/qwen0_5b

The --data dir must hold train.jsonl and val.jsonl in chat format
({"messages":[system,user,assistant]}), produced by build_llm_dataset_v3.py +
prepare_data.py.
"""

import argparse
import os
import time

import torch
from datasets import load_dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer

# LoRA recipe. Stage-2 defaults follow the paper's fixed config (Table 4.8):
# r=8, alpha=2r=16. --r/--alpha override for the bake-off (Stage-1 used r=16/α=32).
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj",
                  "gate_proj", "up_proj", "down_proj"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="HF base model id")
    ap.add_argument("--data", required=True, help="dir with train.jsonl / val.jsonl")
    ap.add_argument("--out", required=True, help="adapter output dir")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--r", type=int, default=8, help="LoRA rank (paper Table 4.8: 8)")
    ap.add_argument("--alpha", type=int, default=16, help="LoRA alpha (paper: α=2r=16)")
    args = ap.parse_args()

    LORA = dict(r=args.r, lora_alpha=args.alpha, lora_dropout=0.05, bias="none",
                task_type="CAUSAL_LM", target_modules=TARGET_MODULES)

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        args.model, torch_dtype=torch.bfloat16, device_map={"": 0})
    model.config.use_cache = False

    ds = load_dataset("json", data_files={
        "train": os.path.join(args.data, "train.jsonl"),
        "val":   os.path.join(args.data, "val.jsonl"),
    })

    sft = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        bf16=True,
        gradient_checkpointing=True,
        logging_steps=20,
        eval_strategy="epoch",
        save_strategy="epoch",
        max_length=args.max_len,
        packing=False,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model, args=sft,
        train_dataset=ds["train"], eval_dataset=ds["val"],
        peft_config=LoraConfig(**LORA),
        processing_class=tok,
    )

    t0 = time.time()
    trainer.train()
    wall = time.time() - t0
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)

    # record fine-tune wall-clock for the scorecard
    with open(os.path.join(args.out, "train_meta.json"), "w") as f:
        import json
        json.dump({"model": args.model, "finetune_wall_s": round(wall, 1),
                   "epochs": args.epochs, "batch": args.batch,
                   "grad_accum": args.grad_accum, "max_len": args.max_len,
                   "lora_r": args.r, "lora_alpha": args.alpha}, f, indent=2)
    print(f"Saved LoRA adapter -> {args.out}  (fine-tune {wall/60:.1f} min)")


if __name__ == "__main__":
    main()
