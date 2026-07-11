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
# ---------------------------------------------------------------------------
# CRASH SAFETY (added after the 80% / attack-type-4-5 crash investigation)
# ---------------------------------------------------------------------------
# Root cause of the earlier "crashes when it reaches attack type 4/5" failure:
# the evidence/isolation/revocation publish path forked TWO subprocesses per
# detection event (a per-file `mkdir -p` via std::system + a doomed `ipfs add`
# via popen). At 80-100% attacker density that is thousands of fork+exec per
# simulated second from a multi-GB-RSS process; fork() then starts failing with
# ENOMEM / trips the OOM killer (or the MEM_CAP cgroup below) in the later,
# higher-intensity phases. Reproduced at pct=80: 5271 evidence files + ~10k
# forks by sim t=18.5s of 288s, RSS climbing 2->~15GB, ~2h wall/run.
#
# The simulator now defaults to --ipfsPublish=false (no per-record fork; CIDs
# stay "local://<path>" exactly as they already were with no IPFS daemon, so
# CSV/dataset content is unchanged) and roots the ipfs-* JSON dirs UNDER
# --outputDir so a parallel sweep keeps small per-run dirs instead of piling
# hundreds of thousands of tiny files into one shared, never-cleaned directory.
#
# This script adds, on top of that fix:
#   * preflight_resources() — verifies the trace input exists and that RAM,
#     free disk and free inodes are sufficient for the planned sweep; sizes
#     MEM_CAP_GB vs N_PARALLEL so the cgroup cap can't itself OOM-kill a
#     legitimate run; aborts early with clear guidance instead of dying hours in.
#   * smoke_test() — a ~1-3 min single short run at the highest percentage that
#     exercises all 6 attack types BEFORE committing to the full multi-hour
#     sweep. If it crashes, the sweep aborts. (SMOKE=0 to skip.)
#   * a per-run pre-launch disk/inode guard so a run is never started onto a
#     nearly-full volume.
#
# Requires (already applied on this branch, commit c30f5ec and after):
#   - routing_test=false passed explicitly (routing_test defaults to true,
#     which forces a 3-vehicle/2-RSU test network instead of the real trace)
#   - AutoConfigureSumoMode() exempts datasetMode=sequential_all6 from its
#     "auto-set simTime from trace length" heuristic, so --simTime is
#     honoured as the per-phase length, not silently inflated
#   - IsMaliciousRsuActiveNow() ramps phase 5 (malicious RSU) the same way
#     phases 1-4 already ramp
#   - --ipfsPublish flag (default false); ipfs-* dirs honour --outputDir
#
# Usage:
#   bash sybil-attack/commands/dataset_sweep_seq6_pct.sh
#   PCTS="20 60 100" SEEDS="1 2" bash sybil-attack/commands/dataset_sweep_seq6_pct.sh
#   SMOKE=0 bash sybil-attack/commands/dataset_sweep_seq6_pct.sh   # skip smoke test
#   SMOKE=only bash sybil-attack/commands/dataset_sweep_seq6_pct.sh # smoke test then exit
#
# Environment overrides (all optional):
#   PCTS           space-separated attacker percentages [default "20 40 60 80 100"]
#   SEEDS          space-separated seeds, one run per (pct, seed) pair [default "1"]
#   SIM_TIME       seconds per phase [default 48 -- 6 phases x 48s = 288s,
#                  safely inside the ~299.9s Bukit Bintang trace]
#   N_PARALLEL     max concurrent jobs [default 1]. Size to RAM, not cores:
#                  floor(available_RAM_GB / EST_PEAK_GB). Verified against a
#                  real single-run peak first (see the original guidance below).
#   STAGGER_SEC    seconds between job starts when N_PARALLEL>1 [default 60]
#   MEM_CAP_GB     per-job memory cap via cgroup, if systemd-run available
#                  [default 16]. This is a HARD KILL backstop, not a soft limit:
#                  set it ABOVE a real run's observed peak, or a legitimate run
#                  gets OOM-killed (rc=137) -- that was part of the old crash.
#   EST_PEAK_GB    assumed per-run peak RSS for N_PARALLEL sizing [default 8]
#   MIN_DISK_GB    minimum free disk to require, per planned run [default 5]
#   MIN_INODES     minimum free inodes to require, per planned run [default 200000]
#   SMOKE          1=run smoke test first (default) | 0=skip | only=smoke then exit
#   SMOKE_SIM_TIME per-phase seconds for the smoke test [default 6 -> 36s total]
#   IPFS_PUBLISH   true|false [default false]. false = no per-record fork storm.
#   FANOUT_RANGE   min,max Sybil fanout per attacker [default "2,20"]
#   INTENSITY      stepped | fixed [default stepped]
#   MOBILITY_MODE  ns-3 mobility_mode parameter [default 5 -- Bukit Bintang]
#   SOLUTION_MODE  detection mode [default 4 -- lightweight]
#
# Outputs (under DS_ABS/pct<PCT>_s<SEED>/):
#   computed_detection_evidence_log.csv, rsu_approval_log.csv, controller_log.csv,
#   attack_phases_seq6.csv, sybil_attackers_seq6.csv, run_meta.json, and the
#   per-run ipfs-* evidence dirs. (communication_log/vehicle_neighbor_table/
#   rssi_verification CSVs are NOT produced under --quietMode=true.)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCTS=${PCTS:-"20 40 60 80 100"}
SEEDS=${SEEDS:-"1"}
SIM_TIME=${SIM_TIME:-48}
N_PARALLEL=${N_PARALLEL:-1}
STAGGER_SEC=${STAGGER_SEC:-60}
MEM_CAP_GB=${MEM_CAP_GB:-16}
EST_PEAK_GB=${EST_PEAK_GB:-8}
MIN_DISK_GB=${MIN_DISK_GB:-5}
MIN_INODES=${MIN_INODES:-200000}
SMOKE=${SMOKE:-1}
SMOKE_SIM_TIME=${SMOKE_SIM_TIME:-6}
IPFS_PUBLISH=${IPFS_PUBLISH:-false}
FANOUT_RANGE=${FANOUT_RANGE:-"2,20"}
INTENSITY=${INTENSITY:-"stepped"}
MOBILITY_MODE=${MOBILITY_MODE:-5}
SOLUTION_MODE=${SOLUTION_MODE:-4}

# Trace file the chosen mobility_mode needs (preflight verifies it exists).
case "$MOBILITY_MODE" in
    3) TRACE_FILE="sybil-attack/inputs/mobility/barcelona/barcelona_mobility.tcl" ;;
    4) TRACE_FILE="sybil-attack/inputs/mobility/kuala-lumpur-cheras/klcp_mobility.tcl" ;;
    5) TRACE_FILE="sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_mobility.tcl" ;;
    *) TRACE_FILE="" ;;
esac

STAMP="$(date +%Y%m%d_%H%M%S)"
DS_REL="sybil-attack/datasets/seq6_pct_sweep_${STAMP}"
DS_ABS="$SIM_DIR/$DS_REL"
CRASH_LOG="$DS_ABS/crashes.log"
mkdir -p "$DS_ABS"

echo "Building simulator once before the sweep..."
( cd "$SIM_DIR" && ./waf build ) || { echo "BUILD FAILED — aborting."; exit 1; }
SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

MEMWRAP=()
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q -p MemoryMax=64M true >/dev/null 2>&1; then
    MEMWRAP=(systemd-run --user --scope -q
             -p "MemoryMax=${MEM_CAP_GB}G" -p "MemorySwapMax=0")
    echo "Per-job memory cap: ${MEM_CAP_GB}G (cgroup, hard kill backstop)."
else
    echo "WARNING: systemd-run --user unavailable — running WITHOUT a memory cap."
fi

PCT_COUNT=$(echo "$PCTS" | wc -w)
SEED_COUNT=$(echo "$SEEDS" | wc -w)
TOTAL_RUNS=$(( PCT_COUNT * SEED_COUNT ))

# ---------------------------------------------------------------------------
# Preflight: fail fast with clear guidance rather than dying hours into a run.
# ---------------------------------------------------------------------------
free_disk_gb() { df -PBG "$DS_ABS" | awk 'NR==2{gsub("G","",$4); print $4}'; }
free_inodes()  { df -Pi  "$DS_ABS" | awk 'NR==2{print $4}'; }

preflight_resources() {
    echo "---------- PREFLIGHT ----------"
    local fail=0

    # 1. Trace input present.
    if [ -n "$TRACE_FILE" ] && [ ! -f "$SIM_DIR/$TRACE_FILE" ]; then
        echo "  FAIL: mobility trace not found: $TRACE_FILE"
        echo "        (mobility_mode=$MOBILITY_MODE needs it). Aborting."
        fail=1
    else
        echo "  OK  : trace present (${TRACE_FILE:-n/a})"
    fi

    # 2. RAM vs N_PARALLEL.
    local avail_gb; avail_gb=$(free -g | awk '/^Mem:/{print $7}')
    local need_gb=$(( N_PARALLEL * EST_PEAK_GB ))
    echo "  RAM : ${avail_gb}G available; plan needs ~${need_gb}G (${N_PARALLEL} x ${EST_PEAK_GB}G)"
    if [ "$need_gb" -gt "$avail_gb" ]; then
        local safe_par=$(( avail_gb / EST_PEAK_GB )); [ "$safe_par" -lt 1 ] && safe_par=1
        echo "  FAIL: N_PARALLEL=$N_PARALLEL x ${EST_PEAK_GB}G peak > ${avail_gb}G available."
        echo "        Re-run with N_PARALLEL=$safe_par (or lower EST_PEAK_GB if you have measured a smaller real peak)."
        fail=1
    fi

    # 3. MEM_CAP must sit above the assumed peak, else the cgroup kills real runs.
    if [ "$MEM_CAP_GB" -le "$EST_PEAK_GB" ]; then
        echo "  WARN: MEM_CAP_GB=$MEM_CAP_GB <= EST_PEAK_GB=$EST_PEAK_GB — the cap could OOM-kill a"
        echo "        legitimate run (that was part of the old crash). Raising cap is safer."
    else
        echo "  OK  : MEM_CAP_GB=$MEM_CAP_GB above assumed peak ${EST_PEAK_GB}G"
    fi

    # 4. Disk + inodes for the whole sweep.
    local disk_gb; disk_gb=$(free_disk_gb)
    local inodes;  inodes=$(free_inodes)
    local need_disk=$(( TOTAL_RUNS * MIN_DISK_GB ))
    local need_inodes=$(( TOTAL_RUNS * MIN_INODES ))
    echo "  DISK: ${disk_gb}G free; sweep wants >= ${need_disk}G (${TOTAL_RUNS} x ${MIN_DISK_GB}G)"
    echo "  INOD: ${inodes} free inodes; sweep wants >= ${need_inodes} (${TOTAL_RUNS} x ${MIN_INODES})"
    if [ "$disk_gb" -lt "$need_disk" ]; then
        echo "  FAIL: not enough free disk on $(df -P "$DS_ABS" | awk 'NR==2{print $6}'). Aborting."
        fail=1
    fi
    if [ "$inodes" -lt "$need_inodes" ]; then
        echo "  FAIL: not enough free inodes (each run writes many small ipfs-* JSON files)."
        echo "        Set IPFS_PUBLISH=false (default) keeps them local; or clear old datasets. Aborting."
        fail=1
    fi

    echo "-------------------------------"
    [ "$fail" -eq 0 ] || { echo "Preflight FAILED — see above."; exit 1; }
    echo "Preflight OK."
}

# ---------------------------------------------------------------------------
# Smoke test: one short run at the highest percentage, all 6 attack types, so
# a config/build/crash problem shows up in minutes instead of hours in.
# ---------------------------------------------------------------------------
smoke_test() {
    local pct; pct=$(echo "$PCTS" | tr ' ' '\n' | sort -rn | head -1)
    local smoke_rel="${DS_REL}/_smoke"
    local smoke_abs="$SIM_DIR/$smoke_rel"
    local log="$smoke_abs/smoke.log"
    rm -rf "$smoke_abs"; mkdir -p "$smoke_abs"
    echo "---------- SMOKE TEST ----------"
    echo "  pct=${pct}%  SIM_TIME=${SMOKE_SIM_TIME}s/phase (6 phases = $((SMOKE_SIM_TIME*6))s total)  $(date +%H:%M:%S)"
    local rc=0
    ( cd "$SIM_DIR" && "${MEMWRAP[@]}" "$SIM_BIN" \
        --mobility_mode=${MOBILITY_MODE} --routing_test=false --sumoAutoConfig=true \
        --sybil_attack_enabled=true --datasetMode=sequential_all6 \
        --solution_mode=${SOLUTION_MODE} --sybil_attack_percentage=${pct} \
        --simTime=${SMOKE_SIM_TIME} --beaconInterval=0.1 \
        --intensitySchedule=${INTENSITY} --sybilFanoutRange=${FANOUT_RANGE} \
        --ipfsPublish=${IPFS_PUBLISH} --seed=1 --runId=smoke \
        --outputDir=${smoke_rel} --quietMode=true ) > "$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "  SMOKE FAILED (rc=${rc}). The full sweep would likely crash the same way."
        echo "  Log: $smoke_rel/smoke.log ; last lines:"
        tail -15 "$log" | sed 's/^/    | /'
        echo "  Aborting before the multi-hour sweep. Fix the above, then re-run."
        exit 1
    fi
    # Confirm it actually reached the last phase (attack type 6).
    local last_t; last_t=$(tail -1 "$smoke_abs/computed_detection_evidence_log.csv" 2>/dev/null | cut -d, -f1)
    echo "  SMOKE OK (rc=0). Reached sim t=${last_t:-?}s of $((SMOKE_SIM_TIME*6))s across all 6 attack phases."
    echo "  ipfs-* JSON dirs written per-run under: $smoke_rel/"
    echo "--------------------------------"
}

echo "=========================================================="
echo " Sequential-All-6 Percentage Sweep — $(date)"
echo " Percentages   : $PCTS"
echo " Seeds         : $SEEDS"
echo " Total runs    : $TOTAL_RUNS"
echo " SIM_TIME      : ${SIM_TIME}s/phase (6 phases = $((SIM_TIME * 6))s total)"
echo " Parallel jobs : $N_PARALLEL  (start stagger ${STAGGER_SEC}s)"
echo " IPFS publish  : $IPFS_PUBLISH  (false = no per-record fork storm)"
echo " Dataset root  : $DS_REL"
echo "=========================================================="

preflight_resources

if [ "$SMOKE" = "only" ]; then
    smoke_test
    echo "SMOKE=only — smoke test passed, exiting before the full sweep."
    exit 0
elif [ "$SMOKE" != "0" ]; then
    smoke_test
fi

run_one() {
    local pct=$1 seed=$2 run_num=$3
    local run_id="pct${pct}_s${seed}"
    local run_rel="${DS_REL}/${run_id}"
    local run_abs="$SIM_DIR/$run_rel"
    local log="$run_abs/run.log"
    mkdir -p "$run_abs"

    # Per-run pre-launch guard: never start a run onto a nearly-full volume.
    local disk_gb; disk_gb=$(free_disk_gb)
    local inodes;  inodes=$(free_inodes)
    if [ "$disk_gb" -lt "$MIN_DISK_GB" ] || [ "$inodes" -lt "$MIN_INODES" ]; then
        echo "  SKIP  run $run_num/$TOTAL_RUNS | id=$run_id  reason=LOW_DISK (${disk_gb}G / ${inodes} inodes free)"
        echo "${run_id}  pct=${pct} seed=${seed}  SKIPPED_LOW_DISK  ${disk_gb}G/${inodes}inodes" >> "$CRASH_LOG"
        return 1
    fi

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
        --ipfsPublish=${IPFS_PUBLISH} \
        --seed=${seed} \
        --runId=${run_id} \
        --outputDir=${run_rel} \
        --quietMode=true ) > "$log" 2>&1
    local rc=$?

    if [ $rc -ne 0 ]; then
        local reason="FAILED (rc=${rc})"
        if [ "$rc" -eq 137 ] || grep -qiE "bad_alloc|out of memory|oom-kill|Killed" "$log" 2>/dev/null; then
            reason="OOM_KILLED (rc=${rc}; hit ${MEM_CAP_GB}G cap — raise MEM_CAP_GB or lower N_PARALLEL)"
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
        # run_one may return non-zero (crash/skip); don't let set -e abort the sweep.
        run_one "$pct" "$seed" "$run_num" || true &
        sleep "$STAGGER_SEC"
    done
done

echo ""
echo "All jobs launched — waiting for completion..."
wait
echo "All jobs finished — $(date)"
echo "Dataset root: $DS_REL"
[ -f "$CRASH_LOG" ] && { echo "Some runs FAILED/SKIPPED — see $CRASH_LOG"; cat "$CRASH_LOG"; } || echo "No crashes."
