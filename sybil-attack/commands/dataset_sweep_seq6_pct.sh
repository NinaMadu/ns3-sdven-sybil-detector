#!/bin/bash
# =============================================================================
# dataset_sweep_seq6_pct.sh — Sequential-all-6 (mode 9) dataset sweep across
# attacker percentages, for the vehicle-tier trust-score notebook.
#
# Each run executes attacks 1->2->3->4->5->6 back-to-back on the full
# Bukit Bintang trace (259 vehicles, 64 RSUs), at one fixed
# --sybil_attack_percentage, with stepped intensity ramping within each
# phase (real behavioral ramp for phases 1-5; see the commit history for
# why phase 6 stays binary). One run per percentage in PCTS x one run per
# seed in SEEDS -- default is the design brief's {20,40,60,80,100}% sweep,
# one seed each.
#
# Requires (already applied on this branch, commit c30f5ec and after):
#   - routing_test=false passed explicitly (routing_test defaults to true,
#     which forces a 3-vehicle/2-RSU test network instead of the real trace)
#   - AutoConfigureSumoMode() exempts datasetMode=sequential_all6 from its
#     "auto-set simTime from trace length" heuristic, so --simTime is
#     honoured as the per-phase length, not silently inflated
#   - IsMaliciousRsuActiveNow() ramps phase 5 (malicious RSU) the same way
#     phases 1-4 already ramp
#
# Usage:
#   bash sybil-attack/commands/dataset_sweep_seq6_pct.sh
#   PCTS="20 60 100" SEEDS="1 2" bash sybil-attack/commands/dataset_sweep_seq6_pct.sh
#
# Environment overrides (all optional):
#   PCTS           space-separated attacker percentages [default "20 40 60 80 100"]
#   SEEDS          space-separated seeds, one run per (pct, seed) pair [default "1"]
#   SIM_TIME       seconds per phase [default 48 -- 6 phases x 48s = 288s,
#                  safely inside the ~299.9s Bukit Bintang trace; the
#                  script's other mode (dataset_sweep_v2.sh) defaults to 60,
#                  which runs the last ~60s of phase 6 on frozen positions]
#   N_PARALLEL     max concurrent jobs [default 1 -- each run uses ~6-8GB
#                  resident; size this to your machine's RAM, not core
#                  count: floor(available_RAM_GB / 8) is a safe starting
#                  point, verified with one run first]
#   STAGGER_SEC    seconds between job starts when N_PARALLEL>1 [default 60]
#   MEM_CAP_GB     per-job memory cap via cgroup, if systemd-run available [default 10]
#   FANOUT_RANGE   min,max Sybil fanout per attacker [default "2,20"]
#   INTENSITY      stepped | fixed [default stepped]
#   MOBILITY_MODE  ns-3 mobility_mode parameter [default 5 -- Bukit Bintang]
#   SOLUTION_MODE  detection mode [default 4 -- lightweight; also populates
#                  computed_detection_evidence_log.csv, which mode 6/"no
#                  detection" would skip]
#
# Outputs (under DS_ABS/pct<PCT>_s<SEED>/):
#   communication_log.csv, vehicle_neighbor_table_log.csv (with
#   traj_shadow_score/traj_shadow_compared), run_meta.json,
#   attack_phases_seq6.csv, sybil_attackers_seq6.csv, rsu_approval_log.csv,
#   controller_log.csv, computed_detection_evidence_log.csv
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCTS=${PCTS:-"20 40 60 80 100"}
SEEDS=${SEEDS:-"1"}
SIM_TIME=${SIM_TIME:-48}
N_PARALLEL=${N_PARALLEL:-1}
STAGGER_SEC=${STAGGER_SEC:-60}
MEM_CAP_GB=${MEM_CAP_GB:-10}
FANOUT_RANGE=${FANOUT_RANGE:-"2,20"}
INTENSITY=${INTENSITY:-"stepped"}
MOBILITY_MODE=${MOBILITY_MODE:-5}
SOLUTION_MODE=${SOLUTION_MODE:-4}

STAMP="$(date +%Y%m%d_%H%M%S)"
DS_REL="sybil-attack/datasets/seq6_pct_sweep_${STAMP}"
DS_ABS="$SIM_DIR/$DS_REL"
CRASH_LOG="$DS_ABS/crashes.log"
mkdir -p "$DS_ABS"

echo "Building simulator once before the sweep..."
( cd "$SIM_DIR" && ./waf build ) || { echo "BUILD FAILED — aborting."; exit 1; }
SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:$LD_LIBRARY_PATH"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

MEMWRAP=()
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q -p MemoryMax=64M true >/dev/null 2>&1; then
    MEMWRAP=(systemd-run --user --scope -q
             -p "MemoryMax=${MEM_CAP_GB}G" -p "MemorySwapMax=0")
    echo "Per-job memory cap: ${MEM_CAP_GB}G (cgroup)."
else
    echo "WARNING: systemd-run --user unavailable — running WITHOUT a memory cap."
fi

PCT_COUNT=$(echo "$PCTS" | wc -w)
SEED_COUNT=$(echo "$SEEDS" | wc -w)
TOTAL_RUNS=$(( PCT_COUNT * SEED_COUNT ))

echo "=========================================================="
echo " Sequential-All-6 Percentage Sweep — $(date)"
echo " Percentages   : $PCTS"
echo " Seeds         : $SEEDS"
echo " Total runs    : $TOTAL_RUNS"
echo " SIM_TIME      : ${SIM_TIME}s/phase (6 phases = $((SIM_TIME * 6))s total)"
echo " Parallel jobs : $N_PARALLEL  (start stagger ${STAGGER_SEC}s)"
echo " Dataset root  : $DS_REL"
echo "=========================================================="

run_one() {
    local pct=$1 seed=$2 run_num=$3
    local run_id="pct${pct}_s${seed}"
    local run_rel="${DS_REL}/${run_id}"
    local run_abs="$SIM_DIR/$run_rel"
    local log="$run_abs/run.log"
    mkdir -p "$run_abs"

    echo "  START run $run_num/$TOTAL_RUNS | id=$run_id  pct=${pct}%  seed=$seed  $(date +%H:%M:%S)"

    ( cd "$SIM_DIR" && "${MEMWRAP[@]}" "$SIM_BIN" \
        --mobility_mode=${MOBILITY_MODE} \
        --routing_test=false \
        --sumoAutoConfig=true \
        --sybil_attack_enabled=true \
        --datasetMode=sequential_all6 \
        --solution_mode=${SOLUTION_MODE} \
        --sybil_attack_percentage=${pct} \
        --simTime=${SIM_TIME} \
        --beaconInterval=0.1 \
        --intensitySchedule=${INTENSITY} \
        --sybilFanoutRange=${FANOUT_RANGE} \
        --seed=${seed} \
        --runId=${run_id} \
        --outputDir=${run_rel} \
        --quietMode=true ) > "$log" 2>&1
    local rc=$?

    if [ $rc -ne 0 ]; then
        local reason="FAILED (rc=${rc})"
        if [ "$rc" -eq 137 ] || grep -qiE "bad_alloc|out of memory|oom-kill|Killed" "$log" 2>/dev/null; then
            reason="OOM_KILLED (rc=${rc}; hit ${MEM_CAP_GB}G cap)"
        elif [ "$rc" -eq 134 ]; then reason="ABORTED (rc=134)"; fi
        echo "  CRASH run $run_num/$TOTAL_RUNS | id=$run_id  reason=${reason}"
        echo "${run_id}  pct=${pct} seed=${seed}  ${reason}  log=${run_rel}/run.log" >> "$CRASH_LOG"
        return 1
    fi

    echo "  DONE  run $run_num/$TOTAL_RUNS | id=$run_id  pct=${pct}%  seed=$seed  $(date +%H:%M:%S)"
}

run_num=0
for pct in $PCTS; do
    for seed in $SEEDS; do
        run_num=$(( run_num + 1 ))
        while [ "$(jobs -rp | wc -l)" -ge "$N_PARALLEL" ]; do sleep 3; done
        run_one "$pct" "$seed" "$run_num" &
        sleep "$STAGGER_SEC"
    done
done

echo ""
echo "All jobs launched — waiting for completion..."
wait
echo "All jobs finished — $(date)"
echo "Dataset root: $DS_REL"
[ -f "$CRASH_LOG" ] && { echo "Some runs FAILED — see $CRASH_LOG"; } || echo "No crashes."
