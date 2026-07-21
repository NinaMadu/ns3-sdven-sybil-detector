#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Stage-3 Ablation D1 driver — LLM-FL vs Local-Only across inter-zone heterogeneity.
#
# Runs the four report-defined experiments (2 conditions x 2 heterogeneity
# endpoints) with IDENTICAL rounds / local budget / seeds / initial adapters, so
# D1 changes only the federation operation. Then collates history.json into one
# D1 results table (collate_d1.py).
#
# This is a LONG run (each experiment trains 3 agents x 4 zones per round for up
# to max_rounds). Launch it under tmux so it survives logout:
#     tmux new -s llmfl 'bash run_d1.sh'
#
# Usage:
#   bash run_d1.sh                 # all 4 experiments, both seeds if configured
#   bash run_d1.sh H0              # only the homogeneous endpoint
#   SEEDS="42 7" bash run_d1.sh    # override seeds
# ---------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(cd "$HERE/../.." && pwd)/.venv/bin/python"

export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg TF_CPP_MIN_LOG_LEVEL=3

ENDPOINTS="${1:-H0 Hmax}"
SEEDS="${SEEDS:-42}"

echo "=== Stage-3 partition (idempotent) ==="
"$PY" "$HERE/partition_by_zone.py"

for seed in $SEEDS; do
  for ep in $ENDPOINTS; do
    for cond in local llm_fl; do
      echo ""; echo "############ $ep / $cond / seed $seed ############"
      "$PY" "$HERE/run_federation.py" --endpoint "$ep" --condition "$cond" \
            --seed "$seed" --resume
    done
  done
done

echo ""; echo "=== collating D1 table ==="
"$PY" "$HERE/collate_d1.py"
echo "=== D1 complete -> $HERE/runs/D1_results.md ==="
