#!/usr/bin/env bash
# ============================================================================
# Safe sequential runner for the three vehicle-tier v2 notebooks.
#   temporal_gru_seq_v3  →  RSSI_Model1_CNN_Federated_v2  →  vehicle_trust_score_model_v2
#
# * PREFLIGHT-GATED : refuses to launch unless ml/fusion/preflight_memory.py says SAFE
#                     and the shared split_map.parquet exists.
# * DISCONNECT-PROOF: the pipeline runs under `setsid nohup`, so closing your SSH
#                     session does NOT kill it.
# * SEQUENTIAL      : one notebook at a time (never concurrent) so memory peaks
#                     don't stack; each notebook frees before the next starts.
# * MONITORABLE     : `status` after reconnecting; a mem-sampler logs RAM/GPU.
#
# USAGE (from anywhere):
#   commands/run_vehicle_tier_v2.sh start     # gate on preflight, then launch detached
#   commands/run_vehicle_tier_v2.sh status    # snapshot: which notebook, RAM, GPU, progress
#   commands/run_vehicle_tier_v2.sh stop      # abort the pipeline
#   commands/run_vehicle_tier_v2.sh preflight # just run the memory check
#
# After `start` you may safely disconnect SSH. Reconnect and run `status` anytime.
# ============================================================================
set -uo pipefail

BASE="/home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35/sybil-attack"
PY="$BASE/ml/.venv/bin/python"
JUP="$BASE/ml/.venv/bin/jupyter"
NBDIR="$BASE/notebooks"
OUTDIR="$BASE/notebooks/outputs"
PREFLIGHT="$BASE/ml/fusion/preflight_memory.py"
MANIFEST="$BASE/ml/fusion/identity_manifest.py"
LOGDIR="$BASE/commands/logs/vehicle_tier_v2"
EXECDIR="$LOGDIR/executed"
PIDFILE="$LOGDIR/pipeline.pid"
MEMPID="$LOGDIR/memsampler.pid"
STATUS="$LOGDIR/status.log"
CURRENT="$LOGDIR/current"
MEMLOG="$LOGDIR/mem.log"

export MPLBACKEND=Agg          # headless: plt.show() is a no-op; never hangs over SSH
export PYTHONUNBUFFERED=1

# run order — GRU first (heaviest), then RSSI, then trust. All read the prebuilt split_map.
NOTEBOOKS=(
  "temporal_gru_seq_v3.ipynb"
  "RSSI_Model1_CNN_Federated_v2.ipynb"
  "vehicle_trust_score_model_v2.ipynb"
)

mkdir -p "$EXECDIR"

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; }

preflight() {
  echo "=== PREFLIGHT  $(date '+%F %T') ==="
  if [ ! -f "$OUTDIR/split_map.parquet" ]; then
    echo "ABORT: shared split_map.parquet missing. Build it first:"
    echo "    $PY $MANIFEST --force"
    return 2
  fi
  local out; out="$("$PY" "$PREFLIGHT" 2>&1)"; local rc=$?
  echo "$out"
  if [ $rc -ne 0 ]; then echo "ABORT: preflight script errored."; return 2; fi
  if echo "$out" | grep -q "RISK"; then
    echo "ABORT: preflight verdict = RISK. Lower MAX_WINDOWS or identity_manifest.KEEP_FRAC and retry."
    return 1
  fi
  echo "=== PREFLIGHT PASSED ==="
  return 0
}

_mem_sampler() {
  while true; do
    local ma; ma=$(awk '/MemAvailable/{printf "%.1fGB", $2/1024/1024}' /proc/meminfo)
    local gpu; gpu=$(nvidia-smi --query-gpu=memory.used,memory.free,utilization.gpu \
                     --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
    echo "$(date '+%F %T') MemAvail=$ma GPU(usedMiB,freeMiB,util%)=$gpu" >> "$MEMLOG"
    sleep 30
  done
}

worker() {
  : > "$MEMLOG"
  _mem_sampler & echo $! > "$MEMPID"
  trap 'kill "$(cat "$MEMPID" 2>/dev/null)" 2>/dev/null' EXIT
  echo "==== PIPELINE START $(date '+%F %T') pid=$$ ====" >> "$STATUS"
  for nb in "${NOTEBOOKS[@]}"; do
    local name="${nb%.ipynb}"
    local log="$LOGDIR/${name}.log"
    echo "$nb" > "$CURRENT"
    echo "$(date '+%F %T') | RUNNING | $nb" >> "$STATUS"
    local t0; t0=$(date +%s)
    "$JUP" nbconvert --to notebook --execute \
        --ExecutePreprocessor.kernel_name=python3 \
        --ExecutePreprocessor.timeout=-1 \
        --output-dir "$EXECDIR" --output "${name}.executed.ipynb" \
        "$NBDIR/$nb" > "$log" 2>&1
    local rc=$? t1; t1=$(date +%s)
    if [ $rc -ne 0 ]; then
      echo "$(date '+%F %T') | FAILED  | $nb (rc=$rc, $((t1-t0))s) — see $log" >> "$STATUS"
      echo "FAILED $nb" > "$CURRENT"
      echo "==== PIPELINE ABORTED $(date '+%F %T') ====" >> "$STATUS"
      exit $rc
    fi
    echo "$(date '+%F %T') | DONE    | $nb ($((t1-t0))s)" >> "$STATUS"
  done
  echo "ALL DONE" > "$CURRENT"
  OUTDIR="$OUTDIR" "$PY" - >> "$STATUS" 2>&1 <<'PYEOF'
import os, pandas as pd
d = os.environ["OUTDIR"]
files = {"rssi":"rssi_vehicle_tier.parquet","temporal":"temporal_vehicle_tier.parquet",
         "trust":"trust_vehicle_tier.parquet"}
have = {k: os.path.join(d, v) for k, v in files.items() if os.path.exists(os.path.join(d, v))}
print("exports:", {k: pd.read_parquet(v).shape for k, v in have.items()})
if len(have) == 3:
    key = ["run_id","claimed_node_id","window_start_seconds","split"]
    dfs = [pd.read_parquet(v)[key].drop_duplicates() for v in have.values()]
    j = dfs[0].merge(dfs[1], on=key).merge(dfs[2], on=key)
    print(f"3-way JOIN on {key}: {len(j):,} matched rows")
PYEOF
  echo "==== PIPELINE ALL DONE $(date '+%F %T') ====" >> "$STATUS"
}

cmd_status() {
  echo "=== vehicle-tier v2 pipeline @ $(date '+%F %T') ==="
  if is_running; then echo "STATE : RUNNING (pid $(cat "$PIDFILE"))"
  else echo "STATE : not running"; fi
  echo "STAGE : $( [ -f "$CURRENT" ] && cat "$CURRENT" || echo 'not started')"
  echo
  echo "--- progress ---"
  [ -f "$STATUS" ] && tail -n 12 "$STATUS" || echo "(no status yet)"
  local cur; cur="$( [ -f "$CURRENT" ] && cat "$CURRENT" )"
  case "$cur" in
    *.ipynb)
      local log="$LOGDIR/${cur%.ipynb}.log"
      echo; echo "--- tail: $cur ---"; tail -n 12 "$log" 2>/dev/null ;;
  esac
  echo; echo "--- resources ---"
  free -h | awk 'NR==1||/Mem:/'
  [ -f "$MEMLOG" ] && echo "last sample: $(tail -n1 "$MEMLOG")"
  nvidia-smi --query-gpu=memory.used,memory.free,utilization.gpu --format=csv,noheader 2>/dev/null \
    | head -1 | sed 's/^/GPU used,free,util: /'
}

case "${1:-help}" in
  start)
    if is_running; then echo "Already running (pid $(cat "$PIDFILE")). Use 'status' or 'stop'."; exit 1; fi
    preflight || { echo "Not launching."; exit 1; }
    : > "$STATUS"; echo "starting" > "$CURRENT"
    setsid nohup "$0" __worker >"$LOGDIR/worker.out" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    echo
    echo "LAUNCHED detached (pid $(cat "$PIDFILE")). It is safe to disconnect SSH now."
    echo "Monitor:  $0 status        |  live:  watch -n 15 $0 status"
    echo "Logs   :  $LOGDIR/"
    ;;
  __worker) worker ;;                       # internal (invoked detached)
  status)   cmd_status ;;
  preflight) preflight ;;
  stop)
    if is_running; then
      kill "$(cat "$PIDFILE")" 2>/dev/null
      pkill -P "$(cat "$PIDFILE")" 2>/dev/null
      [ -f "$MEMPID" ] && kill "$(cat "$MEMPID")" 2>/dev/null
      echo "STOP requested for pid $(cat "$PIDFILE"). (a running nbconvert may take a moment to exit)"
      echo "$(date '+%F %T') | STOPPED | by user" >> "$STATUS"
    else echo "Not running."; fi
    ;;
  *)
    sed -n '2,20p' "$0" ;;
esac
