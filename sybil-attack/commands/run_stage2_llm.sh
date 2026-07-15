#!/usr/bin/env bash
# ============================================================================
# Stage-2 LLM 3-agent decision layer — end-to-end runner.
#
#   ensemble : Eq 3.18 fusion head -> Eq 3.20 RSU ensemble -> rebuild c_i
#   datasets : build the three per-agent SFT datasets (data_a1/a2/a3)
#   train    : fine-tune the 3 LoRA adapters over ONE shared Qwen2.5-1.5B base
#   eval     : Eq 3.22 trust-weighted consensus + per-agent & consensus scorecards
#   all      : ensemble -> datasets -> train -> eval, in order
#
# * DISCONNECT-PROOF : each phase runs under `setsid nohup`; closing SSH won't kill it.
# * SEQUENTIAL       : one GPU job at a time (3 adapters trained back-to-back).
# * MONITORABLE      : `status` / `logs` after reconnecting.
#
# USAGE (from anywhere):
#   commands/run_stage2_llm.sh all       # full pipeline, detached
#   commands/run_stage2_llm.sh ensemble  # just the ŷ_ens rebuild (fast, foreground)
#   commands/run_stage2_llm.sh status
#   commands/run_stage2_llm.sh logs
#   commands/run_stage2_llm.sh stop
# ============================================================================
set -uo pipefail

BASE="/home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35/sybil-attack"
PY="$BASE/ml/.venv/bin/python"
FUSION="$BASE/ml/fusion"
COMMON="$BASE/ml/llm/common"          # constants, build_context_vector, train_lora_generic
STAGE2="$BASE/ml/llm/stage2_agents"   # agents, datasets, consensus, adapters
LOGDIR="$BASE/commands/logs/stage2_llm"
PIDFILE="$LOGDIR/pipeline.pid"
LOG="$LOGDIR/run.log"
mkdir -p "$LOGDIR"

BASE_MODEL="Qwen/Qwen2.5-1.5B-Instruct"
A1="$STAGE2/adapters/qwen1_5b_a1"
A2="$STAGE2/adapters/qwen1_5b_a2"
A3="$STAGE2/adapters/qwen1_5b_a3"

# ml/.venv has TF+Keras3; these three vars are REQUIRED or trl import dies (see memory).
export TF_USE_LEGACY_KERAS=1
export TOKENIZERS_PARALLELISM=false
export MPLBACKEND=Agg
export PYTHONUNBUFFERED=1

run_ensemble() {
  echo "== Eq 3.18 fusion head ==";          "$PY" "$FUSION/train_fusion_head.py" || return 1
  echo "== Eq 3.19/3.20 RSU ensemble ==";     "$PY" "$FUSION/rsu_ensemble.py"      || return 1
  echo "== rebuild c_i with ŷ_ens ==";        ( cd "$COMMON" && "$PY" build_context_vector.py ) || return 1
}
run_datasets() { ( cd "$STAGE2" && "$PY" build_agent_datasets.py ); }
run_train() {
  ( cd "$STAGE2" && \
    echo "== train a1 (message-pattern) ==" && "$PY" "$COMMON/train_lora_generic.py" --model "$BASE_MODEL" --data "$STAGE2/data_a1" --out "$A1" --r 8 --alpha 16 && \
    echo "== train a2 (trust) =="           && "$PY" "$COMMON/train_lora_generic.py" --model "$BASE_MODEL" --data "$STAGE2/data_a2" --out "$A2" --r 8 --alpha 16 && \
    echo "== train a3 (temporal) =="        && "$PY" "$COMMON/train_lora_generic.py" --model "$BASE_MODEL" --data "$STAGE2/data_a3" --out "$A3" --r 8 --alpha 16 )
}
run_eval() {
  ( cd "$STAGE2" && "$PY" consensus_eval.py --base "$BASE_MODEL" --adapters "$A1" "$A2" "$A3" )
}

run_all() { run_ensemble && run_datasets && run_train && run_eval; }

launch() {   # $1 = function name, detached
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "already running (pid $(cat "$PIDFILE")); use 'stop' first"; exit 1
  fi
  echo "launching '$1' detached -> $LOG"
  setsid nohup bash -c "$(declare -f run_ensemble run_datasets run_train run_eval run_all);
    export TF_USE_LEGACY_KERAS=1 TOKENIZERS_PARALLELISM=false MPLBACKEND=Agg PYTHONUNBUFFERED=1;
    PY='$PY'; FUSION='$FUSION'; COMMON='$COMMON'; STAGE2='$STAGE2'; BASE_MODEL='$BASE_MODEL'; A1='$A1'; A2='$A2'; A3='$A3';
    echo \"[\$(date)] START $1\"; $1; rc=\$?; echo \"[\$(date)] DONE $1 rc=\$rc\"; exit \$rc" \
    >"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  echo "pid $(cat "$PIDFILE")  —  monitor: commands/run_stage2_llm.sh logs"
}

case "${1:-}" in
  ensemble) run_ensemble ;;                       # fast, run in foreground
  datasets) run_datasets ;;
  train)    launch run_train ;;
  eval)     launch run_eval ;;
  all)      launch run_all ;;
  status)
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "RUNNING pid $(cat "$PIDFILE")"; else echo "not running"; fi
    nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader 2>/dev/null
    tail -n 5 "$LOG" 2>/dev/null ;;
  logs)  tail -n 60 -f "$LOG" ;;
  stop)  [[ -f "$PIDFILE" ]] && kill -- -"$(cat "$PIDFILE")" 2>/dev/null; rm -f "$PIDFILE"; echo stopped ;;
  *) echo "usage: $0 {ensemble|datasets|train|eval|all|status|logs|stop}"; exit 1 ;;
esac
