#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Package exactly what the cluster needs for the LLM-FL convergence run.
#
# Produces  llmfl_cluster_bundle.tar.gz  (~30 MB) containing:
#   llm/common/            constants, context builder, eval helpers
#   llm/common/context/    c_i.parquet  (the canonical Eq 3.31 context table)
#   llm/stage2_agents/     agents.py + consensus_infer.py (prompts + Eq 3.22 math)
#   llm/stage3_agents/     all Stage-3 code + both configs
#
# NOT included (regenerated or downloaded on the cluster):
#   data_fl/       ~505 MB - regenerated deterministically by partition_by_zone.py
#   runs/          ~4.9 GB - the previous 5-round outputs; not needed for a fresh run
#   base model     ~2.9 GB - downloaded from HF on the cluster (or rsync'd separately)
#
# Usage:  bash make_cluster_bundle.sh
# ---------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # .../llm/stage3_agents
LLM="$(cd "$HERE/.." && pwd)"                             # .../llm
OUT="$HERE/llmfl_cluster_bundle.tar.gz"

cd "$LLM/.."                                              # .../ml  (tar paths start at llm/)

tar -czf "$OUT" \
  llm/common/constants.py \
  llm/common/build_llm_dataset.py \
  llm/common/build_context_vector.py \
  llm/common/eval_fusion.py \
  llm/common/train_lora_generic.py \
  llm/common/context/c_i.parquet \
  llm/stage2_agents/agents.py \
  llm/stage2_agents/consensus_infer.py \
  llm/stage3_agents/*.py \
  llm/stage3_agents/*.json \
  llm/stage3_agents/*.sh \
  llm/stage3_agents/*.md

echo "wrote $OUT"
ls -la "$OUT" | awk '{print "  size: "$5" bytes"}'
echo
echo "contents:"
tar -tzf "$OUT" | sed 's/^/  /'
