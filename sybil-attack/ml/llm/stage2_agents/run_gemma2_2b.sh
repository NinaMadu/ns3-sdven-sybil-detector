#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Stage-2 (3-agent consensus) re-run on Gemma-2-2B-Instruct (Google's open
# "Gemini-family" model — the local, LoRA-fine-tunable counterpart to the
# closed Gemini API, built from the same research line).
#
# This is a NEW, self-contained driver. It does NOT touch any existing code,
# adapters, scorecards, or preds. It only:
#   - trains 3 LoRA agents on Gemma-2-2B    -> adapters/gemma2_2b_a{1,2,3}
#   - runs consensus_eval with that base    -> scorecards_gemma2_2b/, new preds
#
# The existing Qwen2.5-1.5B run (adapters/qwen1_5b_a*, scorecards/, preds/
# stage2_agent_preds.parquet) and the Llama-3.2-1B run (adapters/llama1b_a*,
# scorecards_llama1b/, preds/stage2_llama1b_agent_preds.parquet) are left
# completely untouched, so all three results stay directly comparable.
#
# Same frozen recipe as the Qwen and Llama runs (r=8, alpha=16, 2 epochs,
# batch 8, grad-accum 2, max-len 1024 -> the train_lora_generic.py defaults),
# so the only thing that changes between the runs is the base LLM.
#
# Usage:
#   bash run_gemma2_2b.sh          # train 3 agents, then consensus eval
#   bash run_gemma2_2b.sh eval     # skip training, just re-run consensus eval
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # .../llm/stage2_agents
LLM_ROOT="$(cd "$HERE/.." && pwd)"                        # .../llm
ML_ROOT="$(cd "$LLM_ROOT/.." && pwd)"                     # .../ml
PY="$ML_ROOT/.venv/bin/python"

BASE="google/gemma-2-2b-it"
TAG="gemma2_2b"

# gated weights are already in the local HF cache -> stay offline, no HF_TOKEN.
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg
# reduce allocator fragmentation for the big Gemma logits tensor
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# Gemma-2 has a 256k-token vocab (vs ~32k-150k for Llama/Qwen), so the fp32
# cross-entropy logits (batch x seq x 256k) OOM a 32 GB GPU at batch 8. Drop the
# micro-batch to 4 and raise grad-accum to 4 -> the EFFECTIVE batch stays 16,
# identical to the Qwen and Llama runs, so the comparison is still apples-to-apples.
# (batch 4 peaks ~20 GB, leaving headroom on the 32 GB card while keeping GPU busy.)
BATCH=4
GRAD_ACCUM=4

ADAPTERS_DIR="$HERE/adapters"
SCORECARDS_DIR="$HERE/scorecards_${TAG}"
PREDS="$HERE/preds/stage2_${TAG}_agent_preds.parquet"
LOG="$HERE/run_${TAG}.log"

mkdir -p "$SCORECARDS_DIR" "$HERE/preds"

echo "=== Stage-2 on $BASE ===" | tee "$LOG"
echo "python : $PY"            | tee -a "$LOG"

# Gemma-2 has no `system` chat role -> build system-folded copies of the agent
# datasets (data_gemma2_2b_a{1,2,3}). Leaves the original data_a* untouched.
echo "--- prep gemma data $(date) ---" | tee -a "$LOG"
"$PY" "$HERE/prep_gemma_data.py" 2>&1 | tee -a "$LOG"

if [ "${1:-train}" != "eval" ]; then
  for a in a1 a2 a3; do
    echo "--- training $TAG/$a $(date) ---" | tee -a "$LOG"
    "$PY" "$LLM_ROOT/common/train_lora_generic.py" \
      --model "$BASE" \
      --data  "$HERE/data_${TAG}_$a" \
      --out   "$ADAPTERS_DIR/${TAG}_$a" \
      --batch "$BATCH" --grad-accum "$GRAD_ACCUM" \
      --r 8 --alpha 16 2>&1 | tee -a "$LOG"
  done
fi

echo "--- consensus eval $(date) ---" | tee -a "$LOG"
"$PY" "$HERE/consensus_eval_gemma.py" \
  --base "$BASE" \
  --adapters "$ADAPTERS_DIR/${TAG}_a1" "$ADAPTERS_DIR/${TAG}_a2" "$ADAPTERS_DIR/${TAG}_a3" \
  --scorecards "$SCORECARDS_DIR" \
  --preds "$PREDS" 2>&1 | tee -a "$LOG"

echo "=== done. scorecards -> $SCORECARDS_DIR ===" | tee -a "$LOG"
