"""
Stage-3 STEP 3 — local FedProx LoRA training for ONE (zone, agent) in one round.

Same recipe as Stage-2 train_lora_generic.py (Qwen base, r=8/alpha=16, bf16, the
7 target modules, lr 2e-4 cosine) with exactly two federated additions:

  1. INIT FROM GLOBAL — a round starts every zone from the same global adapter
     (Eq 3.32 output of the previous round). Round 1 starts from a fresh LoRA init.
  2. FedProx PROXIMAL TERM (Eq 3.33) — local loss gets  (mu/2)*Σ_p ||p - p_global||²
     over the trainable LoRA params, anchoring local drift to the round-start
     global adapter. mu=0 recovers plain local training / FedAvg.

The saved adapter contains ONLY the bf16 LoRA A/B tensors + adapter_config.json —
no optimizer state, no epoch checkpoints, no tokenizer. This is the fix for the
supervisor's Issue 2 (adapters were ~15x too large): each head is now ~18.5 MB,
the size a Qwen2.5-1.5B r=8 LoRA should be, so Omega/zeta_LoRA are honest.

Run (called by run_federation.py, but standalone-usable):
    ml/.venv/bin/python fedprox_train.py \
        --agent a1 --data data_fl/H0/a1/zone_1 \
        --init-adapter runs/<exp>/round_000/global/a1 \
        --out runs/<exp>/round_001/local/H0/zone_1/a1 --mu 0.01
"""

import argparse
import json
import os
import time

import torch
from datasets import load_dataset
from peft import LoraConfig, PeftModel, get_peft_model
from peft.utils import get_peft_model_state_dict
from safetensors.torch import save_file
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer

TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj",
                  "gate_proj", "up_proj", "down_proj"]


class FedProxTrainer(SFTTrainer):
    """SFTTrainer + FedProx proximal penalty over trainable LoRA params."""

    def __init__(self, *a, fedprox_mu=0.0, fedprox_ref=None, **kw):
        super().__init__(*a, **kw)
        self.fedprox_mu = float(fedprox_mu)
        self.fedprox_ref = fedprox_ref or {}      # name -> global-start tensor (detached)

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        out = super().compute_loss(model, inputs, return_outputs=return_outputs,
                                   num_items_in_batch=num_items_in_batch)
        loss, outputs = (out if return_outputs else (out, None))
        if self.fedprox_mu > 0 and self.fedprox_ref:
            prox = loss.new_zeros(())
            for n, p in model.named_parameters():
                if p.requires_grad and n in self.fedprox_ref:
                    prox = prox + ((p - self.fedprox_ref[n]) ** 2).sum()
            loss = loss + 0.5 * self.fedprox_mu * prox
        return (loss, outputs) if return_outputs else loss


def build_model(base, init_adapter, lora_cfg, device=0):
    """Load frozen base + attach a TRAINABLE LoRA: either resumed from a global
    adapter (init_adapter) or freshly initialised (round 1)."""
    tok = AutoTokenizer.from_pretrained(base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.bfloat16,
                                                 device_map={"": device})
    model.config.use_cache = False
    if init_adapter and os.path.exists(os.path.join(init_adapter, "adapter_config.json")):
        model = PeftModel.from_pretrained(model, init_adapter, is_trainable=True)
    else:
        model = get_peft_model(model, LoraConfig(
            r=lora_cfg["r"], lora_alpha=lora_cfg["alpha"], lora_dropout=lora_cfg["dropout"],
            bias="none", task_type="CAUSAL_LM", target_modules=lora_cfg["target_modules"]))
    return tok, model


def snapshot_trainable(model):
    """Detached clone of every trainable param = FedProx global-start reference."""
    return {n: p.detach().clone()
            for n, p in model.named_parameters() if p.requires_grad}


def save_bf16_adapter(model, out):
    """Write ONLY adapter_config.json + bf16 adapter_model.safetensors. No
    optimizer, no checkpoints, no tokenizer -> ~18.5 MB, fixes Issue 2."""
    os.makedirs(out, exist_ok=True)
    # peft writes a correct adapter_config.json (target_modules, r, alpha, ...)
    model.save_pretrained(out, safe_serialization=True)
    sd = {k: v.to(torch.bfloat16).contiguous()
          for k, v in get_peft_model_state_dict(model).items()}
    save_file(sd, os.path.join(out, "adapter_model.safetensors"), metadata={"format": "pt"})
    n_params = sum(v.numel() for v in sd.values())
    size_mb = os.path.getsize(os.path.join(out, "adapter_model.safetensors")) / 1e6
    return n_params, round(size_mb, 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-1.5B-Instruct")
    ap.add_argument("--agent", required=True)
    ap.add_argument("--init-only", action="store_true",
                    help="build a fresh untrained LoRA and save it (round-0 shared init); no --data needed")
    ap.add_argument("--data", default="", help="dir holding train.jsonl for this zone/agent")
    ap.add_argument("--init-adapter", default="", help="global adapter to start from ('' = fresh)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mu", type=float, default=0.01)
    ap.add_argument("--epochs", type=float, default=1)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--r", type=int, default=8)
    ap.add_argument("--alpha", type=int, default=16)
    ap.add_argument("--dropout", type=float, default=0.05)
    args = ap.parse_args()

    lora_cfg = {"r": args.r, "alpha": args.alpha, "dropout": args.dropout,
                "target_modules": TARGET_MODULES}

    if args.init_only:
        torch.manual_seed(0)                       # deterministic shared round-0 init
        _tok, model = build_model(args.base, "", lora_cfg)
        n_params, size_mb = save_bf16_adapter(model, args.out)
        json.dump({"agent": args.agent, "init_only": True,
                   "adapter_params": n_params, "adapter_size_mb": size_mb,
                   "lora_r": args.r, "lora_alpha": args.alpha},
                  open(os.path.join(args.out, "train_meta.json"), "w"), indent=2)
        print(f"[{args.agent}] fresh init -> {args.out}  {size_mb} MB")
        return

    if not args.data:
        ap.error("--data is required unless --init-only")
    tok, model = build_model(args.base, args.init_adapter, lora_cfg)
    ref = snapshot_trainable(model) if args.mu > 0 else None

    ds = load_dataset("json", data_files={"train": os.path.join(args.data, "train.jsonl")})

    sft = SFTConfig(
        output_dir=args.out, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch, gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.03,
        bf16=True, gradient_checkpointing=True, logging_steps=20,
        eval_strategy="no", save_strategy="no",           # <- no checkpoints/optimizer on disk
        max_length=args.max_len, packing=False, report_to="none")

    trainer = FedProxTrainer(model=model, args=sft, train_dataset=ds["train"],
                             processing_class=tok, peft_config=None,
                             fedprox_mu=args.mu, fedprox_ref=ref)

    t0 = time.time()
    tr = trainer.train()
    wall = time.time() - t0

    n_params, size_mb = save_bf16_adapter(model, args.out)
    n_train = len(ds["train"])
    json.dump({"agent": args.agent, "data": args.data, "init_adapter": args.init_adapter,
               "mu": args.mu, "n_train_examples": n_train, "train_wall_s": round(wall, 1),
               "final_loss": round(float(tr.training_loss), 4),
               "adapter_params": n_params, "adapter_size_mb": size_mb,
               "epochs": args.epochs, "lora_r": args.r, "lora_alpha": args.alpha},
              open(os.path.join(args.out, "train_meta.json"), "w"), indent=2)
    print(f"[{args.agent}] saved {args.out}  {n_train} ex  {wall/60:.1f} min  "
          f"{size_mb} MB  loss={tr.training_loss:.4f}")


if __name__ == "__main__":
    main()
