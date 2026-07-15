# Stage 2 — paper-faithful 3-agent LLM decision layer (current)

Stage 1 was a **single** 7-class LoRA head over the Eq 3.31 context `c_i`
(`qwen0_5b_v2`, MCC 0.997 / FP 0.0). Stage 2 implements the paper's full Tier-2/3
design (§3.4.3, §4.6): **three specialized LoRA agents sharing one frozen base**
(`Qwen2.5-1.5B-Instruct`), combined by a trust-weighted SDN consensus.

**Equation chain built here (all 7-class):**

| Eq | Module | Output |
|----|--------|--------|
| 3.18 OBU fusion `ŷ_i=σ(w·[φ_rssi‖φ_temp‖φ_trust])` | `../fusion/train_fusion_head.py` | `outputs/fusion_head.parquet` |
| 3.19/3.20 RSU ensemble `ŷ_ens=λ1ŷ_i+λ2p̄_temp+λ3p̄_rssi` | `../fusion/rsu_ensemble.py` | `outputs/ensemble_yhat.parquet` (+`ensemble_lambdas.json`) |
| 3.31 context `c_i` (+`ŷ_ens`) | `build_context_vector.py` | `context/c_i.parquet` |
| — 3 agent datasets (shared context, specialized roles) | `agents.py` + `build_agent_datasets.py` | `data_a1/`, `data_a2/`, `data_a3/` |
| 3.21 agent decisions `(d_a, reason_a)` | `train_lora_generic.py --r 8 --alpha 16` | `adapters/qwen1_5b_a{1,2,3}` |
| 3.22 consensus `D_global=1[Σ ω_a d_a ≥ θ]` | `consensus_eval.py` | `scorecards/stage2_*.json`, `preds/stage2_agent_preds.parquet` |

**Agents (a1 message-pattern, a2 trust, a3 temporal)** all see the SAME `c_i`
(per §4.6.2); only the role system-prompt and the reasoning target differ, so each
LoRA adapter specializes while staying label-consistent. `ω` is uniform (1/3),
`θ_consensus` is calibrated on val by max-MCC; a robustness ablation zeroes each
agent's weight to demonstrate the Eq 3.22 down-weighting property.

**Run it** (needs `TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg`):

```
commands/run_stage2_llm.sh all        # ensemble → datasets → train 3 → consensus eval (detached)
commands/run_stage2_llm.sh ensemble   # just Eq 3.18/3.20 + c_i rebuild (fast)
commands/run_stage2_llm.sh status | logs | stop
```

Runs in `ml/.venv` (torch 2.8/cu128, transformers/peft/trl, RTX 5090). ~5 h to
train all three adapters sequentially.

---

# Full-mode Sybil detector — LLM fusion head + bake-off  (Stage-1 history)

The paper's **full-mode detector** is a 3-tier ensemble whose decision head is a
fine-tuned LLM. Six ML sub-models (trained by the notebooks) each emit a signal;
the fusion head reads a per-`(claimed_id, window)` **evidence JSON** and emits a
**verdict JSON** `{verdict, attack_type, confidence, reasoning}` over the 6-class
taxonomy `legitimate | outsider | sim | nonsim | indirect | malicious_rsu`.

**Design principle:** everything except the base LLM is frozen to the paper — the
six sub-models, the evidence→verdict schema, the LoRA recipe, the split, the
metrics. Only the base LLM varies, chosen by an empirical **bake-off**.

## Sub-models (per paper, unchanged) → evidence fields

| Tier | Notebook | Artifact | Signal |
|---|---|---|---|
| Vehicle | RSSI_Model1_CNN_Federated | `rssi_cnn_federated.pt` | `phi_rssi` |
| Vehicle | temporal_gru_seq_v2.1 | `temporal_federated_gru_hier.pt` | `phi_temp[32]`, `y_hat_i`, 6-class probs |
| Vehicle | vehicle_trust_score_model | `vehicle_trust_mlp_weights.json` | `T_composite` (+components) |
| RSU | RSSI_Model2_XGBoost_RSU | `rssi_xgb_model.pkl` | `pbar_rssi` |
| RSU | temporal_xgb_seq_v2.1 | `rsu_temporal_xgb.json` | `p_bar_temp`, 5-class probs |
| RSU | rsu_trust_score_model | `rsu_trust_mlp_weights.json` | `consensus_trust` |

## Pipeline

```
build_evidence.py         # 6 sub-models -> evidence JSONL  (needs pct100_s1 logs; TODO after sim finishes)
build_llm_dataset_v3.py   # evidence -> {system,user,assistant} JSONL, 6-class, balanced train (TODO)
prepare_data.py           # -> data/{train,val,test}.jsonl  (reuse ml/finetune/prepare_data.py)
bakeoff.py                # for each candidate: train_lora_generic.py -> eval_fusion.py -> scorecard
                          #   -> scorecards/bakeoff_summary.csv  (pick winner on Pareto frontier)
run_full_mode.py          # deploy the winning adapter on a run (TODO)
```

## Bake-off candidates (`candidates.py`)

Qwen2.5 ladder 0.5B / 1.5B / 3B / 7B (ungated, Apache-2.0) + cross-family
Llama-3.2-1B + Gemma-2-2B (**gated — need HF license acceptance + a valid
HF_TOKEN**; `--skip-gated` drops them). 7B is the accuracy *ceiling* reference.

**Selection:** Pareto frontier over (quality: MCC/macro-F1) vs (latency ms/window)
vs (size: params/VRAM). Pick the smallest/fastest model within a small margin of
the 7B ceiling.

## Environment

LLM/LoRA runs in the **py3.11 GPU venv** `../../../../Group 35/CV Project/smart-road-assistant/.venv`
(torch 2.12/cu13, transformers 5.12, peft 0.19, trl 1.7; sentencepiece added for
Gemma). NOT `ml/.venv` (lacks transformers/peft/trl). GPU: RTX 5090 32 GB.

## Status

`pct100_s1` sim must finish all 6 phases before `build_evidence.py` runs
(sequential phases → a partial run is missing whole classes). The harness here
(`candidates.py`, `train_lora_generic.py`, `eval_fusion.py`, `bakeoff.py`) is
data-independent and ready; the two data builders are the remaining pieces.
