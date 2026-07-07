#!/bin/bash
# =============================================================================
# dataset_sweep_v2.sh — Dataset generation sweep for v2 modes:
#
#   Mode 1 — ATTACK_SEQUENTIAL_ALL6  (--datasetMode=sequential_all6)
#     One run executes attacks 1→2→3→4→5→6 back-to-back, each for SIM_TIME
#     seconds. Stepped-intensity sub-windows provide gradual attacker ramp.
#     Runs across SEEDS_M1 reproducible seeds.
#
#   Mode 2 — ATTACK_ZONE_CONCURRENT  (--datasetMode=zone_concurrent)
#     Multiple variants active simultaneously in geographic zones.
#     Runs across ZONE_PROFILES × SEEDS_M2 (all combinations).
#
# Outputs (under DS_ABS/<run_id>/):
#   communication_log.csv, run_meta.json, attack_phases_seq6.csv (mode 1),
#   sybil_attackers_mode8.csv (mode 2), rsu_approval_log.csv, controller_log.csv
#
# Merge outputs (under DS_ABS/):
#   merged_communication_log.csv — all runs concatenated (header preserved once)
#   class_distribution.csv       — label counts per run_id and attack_type_label
#   crashes.log                  — details of any failed runs
#
# Usage:
#   bash sybil-attack/commands/dataset_sweep_v2.sh
#   SIM_TIME=120 N_PARALLEL=4 bash sybil-attack/commands/dataset_sweep_v2.sh
#
# Environment overrides (all optional):
#   SIM_TIME       seconds per phase for mode 1, total sim for mode 2 [default 60]
#   N_PARALLEL     max concurrent jobs [default 4]
#   STAGGER_SEC    seconds between job starts [default 60]
#   MEM_CAP_GB     per-job memory cap [default 8]
#   SEEDS_M1       space-separated seeds for mode 1 [default "1 2 3"]
#   SEEDS_M2       space-separated seeds for mode 2 [default "1 2 3"]
#   ZONE_PROFILES  space-separated profile names (without path prefix) [default see below]
#   ATK_PCT        attacker percentage for sequential_all6 runs [default 50]
#   FANOUT_RANGE   min,max fanout e.g. "2,20" [default "2,20"]
#   INTENSITY      stepped | fixed [default stepped]
#   MOBILITY_MODE  ns-3 mobility_mode parameter [default 5]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

SIM_TIME=${SIM_TIME:-60}
N_PARALLEL=${N_PARALLEL:-4}
STAGGER_SEC=${STAGGER_SEC:-60}
MEM_CAP_GB=${MEM_CAP_GB:-8}
SEEDS_M1=${SEEDS_M1:-"1 2 3"}
SEEDS_M2=${SEEDS_M2:-"1 2 3"}
ATK_PCT=${ATK_PCT:-50}
FANOUT_RANGE=${FANOUT_RANGE:-"2,20"}
INTENSITY=${INTENSITY:-"stepped"}
MOBILITY_MODE=${MOBILITY_MODE:-5}

# Zone profile basenames (resolved relative to sybil-attack/inputs/).
ZONE_PROFILES=${ZONE_PROFILES:-"zone_profiles_default zone_profiles_ctrl zone_profiles_heavy"}

STAMP="$(date +%Y%m%d_%H%M%S)"
DS_REL="sybil-attack/datasets/dataset_v2_${STAMP}"
DS_ABS="$SIM_DIR/$DS_REL"
TMP_DIR="$DS_ABS/.tmp"
CRASH_LOG="$DS_ABS/crashes.log"

mkdir -p "$DS_ABS" "$TMP_DIR"

# ── Build once ─────────────────────────────────────────────────────────────────
echo "Building simulator once before the sweep..."
( cd "$SIM_DIR" && ./waf build ) || { echo "BUILD FAILED — aborting."; exit 1; }
SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:$LD_LIBRARY_PATH"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

# ── Memory cap via systemd-run ─────────────────────────────────────────────────
MEMWRAP=()
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q -p MemoryMax=64M true >/dev/null 2>&1; then
    MEMWRAP=(systemd-run --user --scope -q
             -p "MemoryMax=${MEM_CAP_GB}G" -p "MemorySwapMax=0")
    echo "Per-job memory cap: ${MEM_CAP_GB}G (cgroup)."
else
    echo "WARNING: systemd-run --user unavailable — running WITHOUT a memory cap."
fi

# ── Count total runs ───────────────────────────────────────────────────────────
M1_COUNT=$(echo "$SEEDS_M1" | wc -w)
M2_PROFILE_COUNT=$(echo "$ZONE_PROFILES" | wc -w)
M2_SEED_COUNT=$(echo "$SEEDS_M2" | wc -w)
M2_COUNT=$(( M2_PROFILE_COUNT * M2_SEED_COUNT ))
TOTAL_RUNS=$(( M1_COUNT + M2_COUNT ))

echo "=========================================================="
echo " Dataset Generation v2  —  $(date)"
echo " Parallel jobs : $N_PARALLEL  (start stagger ${STAGGER_SEC}s)"
echo " Total runs    : $TOTAL_RUNS  (Mode1=$M1_COUNT  Mode2=$M2_COUNT)"
echo " SIM_TIME      : ${SIM_TIME}s (per-phase for mode 1)"
echo " Dataset root  : $DS_REL"
echo " Attacker pct  : ${ATK_PCT}%   Fanout: ${FANOUT_RANGE}   Intensity: ${INTENSITY}"
echo "=========================================================="

# ── Worker: Mode 1 (sequential_all6) ──────────────────────────────────────────
run_mode1() {
    local seed=$1 run_num=$2
    local run_id="seq6_s${seed}"
    local run_rel="${DS_REL}/${run_id}"
    local run_abs="$SIM_DIR/$run_rel"
    local log="$run_abs/run.log"
    mkdir -p "$run_abs"

    echo "  START [Mode1] run $run_num/$TOTAL_RUNS | id=$run_id  seed=$seed  $(date +%H:%M:%S)"

    ( cd "$SIM_DIR" && "${MEMWRAP[@]}" "$SIM_BIN" \
        --mobility_mode=${MOBILITY_MODE} \
        --routing_test=false \
        --sybil_attack_enabled=true \
        --datasetMode=sequential_all6 \
        --sybil_attack_percentage=${ATK_PCT} \
        --simTime=${SIM_TIME} \
        --beaconInterval=0.1 \
        --sumoAutoConfig=true \
        --intensitySchedule=${INTENSITY} \
        --sybilFanoutRange=${FANOUT_RANGE} \
        --seed=${seed} \
        --runId=${run_id} \
        --outputDir=${run_rel} ) > "$log" 2>&1
    local rc=$?

    if [ $rc -ne 0 ]; then
        local reason="FAILED (rc=${rc})"
        if [ "$rc" -eq 137 ] || grep -qiE "bad_alloc|out of memory|oom-kill|Killed" "$log" 2>/dev/null; then
            reason="OOM_KILLED (rc=${rc}; hit ${MEM_CAP_GB}G cap)"
        elif [ "$rc" -eq 134 ]; then reason="ABORTED (rc=134)"; fi
        echo "  CRASH [Mode1] run $run_num/$TOTAL_RUNS | id=$run_id  reason=${reason}"
        echo "${run_id}  mode=seq6 seed=${seed}  ${reason}  log=${run_rel}/run.log" >> "$CRASH_LOG"
        echo "FAILED" > "$TMP_DIR/${run_id}.status"
        return 1
    fi

    echo "  DONE  [Mode1] run $run_num/$TOTAL_RUNS | id=$run_id  seed=$seed  $(date +%H:%M:%S)"
    echo "OK" > "$TMP_DIR/${run_id}.status"
}

# ── Worker: Mode 2 (zone_concurrent) ──────────────────────────────────────────
run_mode2() {
    local profile=$1 seed=$2 run_num=$3
    local profile_base="${profile##*/}"
    profile_base="${profile_base%.csv}"
    local run_id="${profile_base}_s${seed}"
    local run_rel="${DS_REL}/${run_id}"
    local run_abs="$SIM_DIR/$run_rel"
    local log="$run_abs/run.log"
    local profile_path="sybil-attack/inputs/${profile}.csv"
    mkdir -p "$run_abs"

    echo "  START [Mode2] run $run_num/$TOTAL_RUNS | id=$run_id  profile=$profile  seed=$seed  $(date +%H:%M:%S)"

    ( cd "$SIM_DIR" && "${MEMWRAP[@]}" "$SIM_BIN" \
        --mobility_mode=${MOBILITY_MODE} \
        --routing_test=false \
        --sybil_attack_enabled=true \
        --datasetMode=zone_concurrent \
        --simTime=${SIM_TIME} \
        --beaconInterval=0.1 \
        --sumoAutoConfig=true \
        --sybilFanoutRange=${FANOUT_RANGE} \
        --zoneProfiles=${profile_path} \
        --seed=${seed} \
        --runId=${run_id} \
        --outputDir=${run_rel} ) > "$log" 2>&1
    local rc=$?

    if [ $rc -ne 0 ]; then
        local reason="FAILED (rc=${rc})"
        if [ "$rc" -eq 137 ] || grep -qiE "bad_alloc|out of memory|oom-kill|Killed" "$log" 2>/dev/null; then
            reason="OOM_KILLED (rc=${rc}; hit ${MEM_CAP_GB}G cap)"
        elif [ "$rc" -eq 134 ]; then reason="ABORTED (rc=134)"; fi
        echo "  CRASH [Mode2] run $run_num/$TOTAL_RUNS | id=$run_id  reason=${reason}"
        echo "${run_id}  mode=zone_concurrent profile=${profile} seed=${seed}  ${reason}  log=${run_rel}/run.log" >> "$CRASH_LOG"
        echo "FAILED" > "$TMP_DIR/${run_id}.status"
        return 1
    fi

    echo "  DONE  [Mode2] run $run_num/$TOTAL_RUNS | id=$run_id  profile=$profile  seed=$seed  $(date +%H:%M:%S)"
    echo "OK" > "$TMP_DIR/${run_id}.status"
}

# ── Launch Mode 1 jobs ─────────────────────────────────────────────────────────
run_num=0
for seed in $SEEDS_M1; do
    run_num=$(( run_num + 1 ))
    while [ "$(jobs -rp | wc -l)" -ge "$N_PARALLEL" ]; do sleep 3; done
    run_mode1 "$seed" "$run_num" &
    sleep "$STAGGER_SEC"
done

# ── Launch Mode 2 jobs ─────────────────────────────────────────────────────────
for profile in $ZONE_PROFILES; do
    for seed in $SEEDS_M2; do
        run_num=$(( run_num + 1 ))
        while [ "$(jobs -rp | wc -l)" -ge "$N_PARALLEL" ]; do sleep 3; done
        run_mode2 "$profile" "$seed" "$run_num" &
        sleep "$STAGGER_SEC"
    done
done

echo ""
echo "All jobs launched — waiting for completion..."
wait
echo "All jobs finished — $(date)"

# ── Merge communication logs ───────────────────────────────────────────────────
echo ""
echo "Merging communication_log.csv files..."
MERGED="$DS_ABS/merged_communication_log.csv"
header_written=false
ok_count=0
fail_count=0

for dir in "$DS_ABS"/*/; do
    csv="$dir/communication_log.csv"
    [ -f "$csv" ] || continue
    if [ "$header_written" = false ]; then
        cat "$csv" > "$MERGED"
        header_written=true
    else
        tail -n +2 "$csv" >> "$MERGED"
    fi
    ok_count=$(( ok_count + 1 ))
done

echo "  Merged $ok_count run(s) into: $MERGED"

# ── Class distribution report ─────────────────────────────────────────────────
echo ""
echo "Computing class distribution..."
DIST_CSV="$DS_ABS/class_distribution.csv"
{
    echo "run_id,attack_type_label,row_count"
    # attack_type_label is the second-to-last column; count by run_id and label.
    if [ -f "$MERGED" ]; then
        # Use awk: header line tells us which columns to use.
        awk -F',' '
            NR==1 {
                for(i=1;i<=NF;i++) {
                    if($i=="run_id")          run_col=i
                    if($i=="attack_type_label") atk_col=i
                }
                next
            }
            run_col && atk_col {
                key=$run_col FS $atk_col
                counts[key]++
            }
            END {
                for(k in counts) print k "," counts[k]
            }
        ' "$MERGED" | sort
    fi
} > "$DIST_CSV"

echo "  Class distribution written to: $DIST_CSV"

# ── Summary ────────────────────────────────────────────────────────────────────
fail_count=$(grep -c "^" "$CRASH_LOG" 2>/dev/null || echo 0)
echo ""
echo "=========================================================="
echo " SWEEP COMPLETE — $(date)"
echo " Successful runs : $ok_count / $TOTAL_RUNS"
[ "$fail_count" -gt 0 ] && echo " Failed runs     : $fail_count  (see $CRASH_LOG)"
echo " Merged CSV      : $MERGED"
echo " Class dist.     : $DIST_CSV"
echo " Dataset root    : $DS_ABS"
echo "=========================================================="

rm -rf "$TMP_DIR"
