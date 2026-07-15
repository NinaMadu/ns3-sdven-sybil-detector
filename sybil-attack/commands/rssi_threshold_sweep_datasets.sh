#!/bin/bash
# =============================================================================
# rssi_threshold_sweep_datasets.sh — Attack percentage sweep (RSSI / mode 2)
#                                     with PER-RUN communication-log capture.
#
# Same sweep as rssi_threshold_sweep.sh, but every run's CSV logs are written to
# their own folder under sybil-attack/datasets/ instead of clobbering the shared
# outputs/ files.  Each run folder is named:
#
#       <attack_type><percentage-3-digits>   =   attack_type*1000 + percentage
#
#   1000 -> attack 1,   0%        2000 -> attack 2,   0%
#   1020 -> attack 1,  20%        3080 -> attack 3,  80%
#   1100 -> attack 1, 100%        5100 -> attack 5, 100%
#
# Each folder contains that run's communication_log.csv (plus the other per-run
# table/awareness logs the simulator emits).
#
# Usage:
#   bash sybil-attack/commands/rssi_threshold_sweep_datasets.sh
#   SIM_TIME=180 bash sybil-attack/commands/rssi_threshold_sweep_datasets.sh
# =============================================================================

# Resolve SIM_DIR from this script's location (commands/ -> sybil-attack/ -> ns-3.35)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SIM_DIR/sybil-attack/outputs"

# Per-run logs go under a timestamped dataset root.
STAMP="$(date +%Y%m%d_%H%M%S)"
DS_REL="sybil-attack/datasets/rssi_sweep_${STAMP}"   # relative to SIM_DIR (sim cwd)
DS_ABS="$SIM_DIR/$DS_REL"
METRICS_CSV="$DS_ABS/rssi_percentage_sweep.csv"
TMP_DIR="$DS_ABS/.tmp"

N_PARALLEL=${N_PARALLEL:-8}

# Seconds to wait between launching consecutive jobs. Staggering the starts means
# the runs do NOT all reach their (memory-heaviest) end phase at the same moment,
# so peak RAM is spread out instead of spiking together. Override with STAGGER_SEC.
STAGGER_SEC=${STAGGER_SEC:-45}

# Hard per-job memory cap (GB). A run that exceeds it is killed by the kernel
# (its cgroup), so a single runaway job can never drag the whole machine into
# swap. Keep N_PARALLEL * MEM_CAP_GB below total RAM (8 * 6 = 48 GB < 61 GB).
MEM_CAP_GB=${MEM_CAP_GB:-6}

ATTACK_TYPES="1 2 3 4 5"
ATTACK_PERCENTAGES="0 20 40 60 80 100"

# ── Detector settings ─────────────────────────────────────────────────────────
# SIM_TIME can be overridden from the environment, e.g.:
#   SIM_TIME=180 bash sybil-attack/commands/rssi_threshold_sweep_datasets.sh
SIM_TIME=${SIM_TIME:-60}
CLUSTER_R=1
DIST1_THRESH=1
STREAK=2
WINDOW=2.0
MIN_SAMPLES=8

mkdir -p "$DS_ABS" "$TMP_DIR"

# Build ONCE here. Parallel `./waf --run` jobs collide on waf's build lock and
# all fail, so the workers run the compiled binary directly instead.
echo "Building simulator once before the sweep..."
( cd "$SIM_DIR" && ./waf build ) || { echo "BUILD FAILED — aborting."; exit 1; }
SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:$LD_LIBRARY_PATH"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

# Wrap each job in a memory-limited cgroup scope if systemd-run is usable.
# MemorySwapMax=0 means an over-limit job is OOM-killed instead of swapping, so
# the machine stays responsive. Falls back to no cap (with a warning) otherwise.
MEMWRAP=()
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q -p MemoryMax=64M true >/dev/null 2>&1; then
    MEMWRAP=(systemd-run --user --scope -q
             -p "MemoryMax=${MEM_CAP_GB}G" -p "MemorySwapMax=0")
    echo "Per-job memory cap: ${MEM_CAP_GB}G (cgroup; over-limit jobs are killed, not swapped)."
else
    echo "WARNING: systemd-run --user unavailable — running WITHOUT a memory cap."
fi

TOTAL_RUNS=$(( $(echo $ATTACK_TYPES | wc -w) * $(echo $ATTACK_PERCENTAGES | wc -w) ))
HEADER="run_id,attack_type,attack_pct,TP,FP,TN,FN,FPR,MDR,Precision,Recall,MCC"

echo "=============================================="
echo " RSSI Percentage Sweep (per-run datasets)  —  $(date)"
echo " Parallel jobs : $N_PARALLEL  (start stagger ${STAGGER_SEC}s)"
echo " Total runs    : $TOTAL_RUNS"
echo " SimTime       : ${SIM_TIME}s"
echo " Dataset root  : $DS_REL"
echo " cluster_r=${CLUSTER_R}m  dist1=${DIST1_THRESH}m  streak=${STREAK}  window=${WINDOW}s  min_samples=${MIN_SAMPLES}"
echo "=============================================="

# ── Worker function ────────────────────────────────────────────────────────────
run_one() {
    local atk=$1 pct=$2 run_num=$3

    # Run id / folder name: attack_type*1000 + percentage (e.g. 1000, 1020, 3080)
    local run_id
    run_id=$(printf "%d%03d" "$atk" "$pct")

    local run_rel="$DS_REL/$run_id"     # passed to --outputDir (relative to SIM_DIR)
    local run_abs="$SIM_DIR/$run_rel"
    mkdir -p "$run_abs"

    local tmp="$TMP_DIR/${run_id}.csv"

    echo "  START  run $run_num/$TOTAL_RUNS | id=$run_id  atk=$atk  pct=${pct}%  $(date +%H:%M:%S)"

    # 0% = no attack — disable sybil entirely
    local atk_enabled="true"
    [ "$pct" -eq 0 ] && atk_enabled="false"

    # Full run output is kept per-run so a crash can be diagnosed afterwards.
    local log="$run_abs/run.log"
    ( cd "$SIM_DIR" && "${MEMWRAP[@]}" "$SIM_BIN" \
         --mobility_mode=5 --solution_mode=2 --routing_test=false \
         --sybil_attack_enabled=${atk_enabled} --sybil_attack_type=${atk} \
         --sybil_attack_percentage=${pct} --simTime=${SIM_TIME} --beaconInterval=0.1 \
         --sumoAutoConfig=true \
         --rssiWindowSec=${WINDOW} --rssiMinSamples=${MIN_SAMPLES} \
         --rssiDist1Thresh=${DIST1_THRESH} \
         --rssiClusterRadius=${CLUSTER_R} --rssiStreak=${STREAK} \
         --outputDir=${run_rel} \
         --sweepMode=true ) > "$log" 2>&1
    local rc=$?

    local result
    result=$(grep "\[RSSI_RESULT\]" "$log")

    if [ -z "$result" ]; then
        # Classify WHY the run produced no result so it can be reported.
        local reason
        if [ "$rc" -eq 137 ] || grep -qiE "bad_alloc|out of memory|oom-kill|Killed" "$log"; then
            reason="OOM_KILLED (rc=${rc}; hit ${MEM_CAP_GB}G cap)"
        elif [ "$rc" -eq 134 ]; then
            reason="ABORTED (rc=134; assert/abort)"
        elif [ "$rc" -eq 139 ]; then
            reason="SEGFAULT (rc=139)"
        else
            reason="FAILED (rc=${rc})"
        fi
        echo "  CRASH  run $run_num/$TOTAL_RUNS | id=$run_id  atk=$atk  pct=${pct}%  reason=${reason}"
        echo "${run_id}  atk=${atk} pct=${pct}%  ${reason}  log=${run_rel}/run.log" >> "$DS_ABS/crashes.log"
        echo "${run_id},${atk},${pct},CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED" > "$tmp"
        return 1
    fi

    local TP FP TN FN FPR MDR PRE REC MCC
    TP=$(echo "$result"  | grep -oP  'TP=\K[0-9]+')
    FP=$(echo "$result"  | grep -oP  'FP=\K[0-9]+')
    TN=$(echo "$result"  | grep -oP  'TN=\K[0-9]+')
    FN=$(echo "$result"  | grep -oP  'FN=\K[0-9]+')
    FPR=$(echo "$result" | grep -oP 'FPR=\K[-0-9.nan]+')
    MDR=$(echo "$result" | grep -oP 'MDR=\K[-0-9.nan]+')
    PRE=$(echo "$result" | grep -oP 'Pre=\K[-0-9.nan]+')
    REC=$(echo "$result" | grep -oP 'Rec=\K[-0-9.nan]+')
    MCC=$(echo "$result" | grep -oP 'MCC=\K[-0-9.nan]+')

    echo "${run_id},${atk},${pct},${TP},${FP},${TN},${FN},${FPR},${MDR},${PRE},${REC},${MCC}" > "$tmp"
    echo "  DONE   run $run_num/$TOTAL_RUNS | id=$run_id  atk=$atk  pct=${pct}%  MCC=$MCC  FPR=$FPR  $(date +%H:%M:%S)"
}

# ── Launch jobs with N_PARALLEL concurrency ────────────────────────────────────
run_num=0
for atk in $ATTACK_TYPES; do
    for pct in $ATTACK_PERCENTAGES; do
        run_num=$(( run_num + 1 ))
        while [ "$(jobs -rp | wc -l)" -ge "$N_PARALLEL" ]; do
            sleep 3
        done
        run_one "$atk" "$pct" "$run_num" &
        # Stagger starts so jobs don't all hit their heavy end-phase together.
        sleep "$STAGGER_SEC"
    done
done

echo ""
echo "All jobs launched — waiting for completion..."
wait
echo "All jobs finished — $(date)"

# ── Merge results in order ─────────────────────────────────────────────────────
echo "$HEADER" > "$METRICS_CSV"
for atk in $ATTACK_TYPES; do
    for pct in $ATTACK_PERCENTAGES; do
        run_id=$(printf "%d%03d" "$atk" "$pct")
        local_csv="$TMP_DIR/${run_id}.csv"
        [ -f "$local_csv" ] && cat "$local_csv" >> "$METRICS_CSV"
    done
done

rm -rf "$TMP_DIR"

echo ""
echo "=============================================="
echo " SWEEP COMPLETE — $(date)"
echo " Per-run logs  : $DS_REL/<run_id>/communication_log.csv"
echo " Summary CSV   : $METRICS_CSV"
if [ -f "$DS_ABS/crashes.log" ]; then
    echo " ----------------------------------------------"
    echo " CRASHED RUNS ($(wc -l < "$DS_ABS/crashes.log")) — see $DS_REL/crashes.log :"
    sed 's/^/   /' "$DS_ABS/crashes.log"
else
    echo " No crashes."
fi
echo "=============================================="
echo ""
cat "$METRICS_CSV"
