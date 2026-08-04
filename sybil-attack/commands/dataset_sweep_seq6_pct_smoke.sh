#!/bin/bash
# =============================================================================
# dataset_sweep_seq6_pct_smoke.sh — short (~30s total) matched-environment
# smoke runs across attacker percentages, mirroring dataset_sweep_seq6_pct.sh's
# config exactly (same flags, same trace, same fanout/intensity), only the
# duration is compressed.
#
# This is a NEW, standalone script — it does not read, call, or modify
# dataset_sweep_seq6_pct.sh or dataset_sweep_v2.sh. Its only job is to verify
# that a given set of --sybil_attack_percentage values run cleanly, start to
# finish through all 6 sequential_all6 phases, on the CURRENT binary, before
# committing to the full multi-hour 288s-per-run sweep.
#
# Matched environment (copied from dataset_sweep_seq6_pct.sh's defaults — the
# config that produced the known-good pct20_s1 / pct40_s1 / pct100_s1 runs):
#   mobility_mode=5 (Bukit Bintang), routing_test=false, sumoAutoConfig=true,
#   datasetMode=sequential_all6, solution_mode=4, beaconInterval=0.1,
#   intensitySchedule=stepped, sybilFanoutRange=2,20, ipfsPublish=false,
#   seed=1
#
# Only the duration changes: --simTime is the PER-PHASE length (sequential_all6
# runs 6 phases back-to-back), so total simulated time = simTime * 6. For a
# ~30s total smoke run, simTime/phase = 5.
#
# Usage:
#   bash sybil-attack/commands/dataset_sweep_seq6_pct_smoke.sh
#   PCTS="20 40 60 80 100" TOTAL_SIM_TIME=30 bash sybil-attack/commands/dataset_sweep_seq6_pct_smoke.sh
#   PCTS="60 80" TOTAL_SIM_TIME=30 bash sybil-attack/commands/dataset_sweep_seq6_pct_smoke.sh
#
# Environment overrides (all optional):
#   PCTS            space-separated attacker percentages [default "20 40 60 80 100"]
#   SEED            seed [default 1, matches existing pct20/40/100 datasets]
#   TOTAL_SIM_TIME  TOTAL simulated seconds across all 6 phases [default 30]
#   OUT_NAME        dataset subfolder name under sybil-attack/datasets/
#                   [default seq6_pct_sweep_smoke_<timestamp>]
#
# Note: SIM_TIME<=12 is only a trap under --sumoAutoConfig when datasetMode is
# NOT sequential_all6 (AutoConfigureSumoMode exempts sequential_all6 from that
# heuristic). This script always passes --datasetMode=sequential_all6, so
# short per-phase values are safe here.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCTS=${PCTS:-"20 40 60 80 100"}
SEED=${SEED:-1}
TOTAL_SIM_TIME=${TOTAL_SIM_TIME:-30}
N_PHASES=6

# ---------------------------------------------------------------------------
# Fixed environment — must match dataset_sweep_seq6_pct.sh's defaults exactly
# so results are comparable to the existing pct20_s1 / pct40_s1 / pct100_s1
# datasets. Do not change these without also re-validating against those.
# ---------------------------------------------------------------------------
MOBILITY_MODE=5
SOLUTION_MODE=4
INTENSITY=stepped
FANOUT_RANGE="2,20"
IPFS_PUBLISH=false

SIM_TIME=$(awk -v t="$TOTAL_SIM_TIME" -v n="$N_PHASES" 'BEGIN{printf "%.6f", t/n}')

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_NAME=${OUT_NAME:-"seq6_pct_sweep_smoke_${STAMP}"}
DS_REL="sybil-attack/datasets/${OUT_NAME}"
DS_ABS="$SIM_DIR/$DS_REL"
mkdir -p "$DS_ABS"

echo "Building simulator (./waf build) ..."
( cd "$SIM_DIR" && ./waf build ) || { echo "BUILD FAILED — aborting."; exit 1; }
SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

echo "=========================================================="
echo " Matched-environment smoke sweep — $(date)"
echo " Percentages   : $PCTS"
echo " Seed          : $SEED"
echo " simTime/phase : ${SIM_TIME}s  (total ${TOTAL_SIM_TIME}s across ${N_PHASES} phases)"
echo " Dataset root  : $DS_REL"
echo "=========================================================="

SUMMARY_ROWS=()
ALL_OK=1

for pct in $PCTS; do
    run_id="pct${pct}_smoke_s${SEED}"
    run_rel="${DS_REL}/${run_id}"
    run_abs="$SIM_DIR/$run_rel"
    mkdir -p "$run_abs"
    log="$run_abs/run.log"

    echo "  START pct=${pct}%  seed=${SEED}  simTime/phase=${SIM_TIME}s (total ${TOTAL_SIM_TIME}s)  $(date +%H:%M:%S)"
    t0=$(date +%s)

    ( cd "$SIM_DIR" && "$SIM_BIN" \
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
        --seed=${SEED} \
        --runId=${run_id} \
        --outputDir=${run_rel} \
        --quietMode=false ) > "$log" 2>&1
    rc=$?
    t1=$(date +%s)
    wall=$(( t1 - t0 ))

    if [ $rc -ne 0 ]; then
        echo "  CRASH pct=${pct}%  rc=${rc}  wall=${wall}s  log=${run_rel}/run.log"
        ALL_OK=0
        SUMMARY_ROWS+=("${pct} ${rc} FAIL - - - ${wall}")
        continue
    fi

    # --- validate: last beacon timestamp should reach close to the expected total
    beacon_csv="$run_abs/communication_log.csv"
    last_t="-"
    beacon_rows=0
    uniq_ids=0
    reached="FAIL"
    if [ -f "$beacon_csv" ]; then
        beacon_rows=$(awk -F, 'NR>1 && $8==1{c++} END{print c+0}' "$beacon_csv")
        uniq_ids=$(awk -F, 'NR>1 && $8==1{print $6}' "$beacon_csv" | sort -u | wc -l | tr -d ' ')
        last_t=$(awk -F, 'NR>1 && $8==1{t=$1} END{print t+0}' "$beacon_csv")
        reached=$(awk -v last="$last_t" -v total="$TOTAL_SIM_TIME" 'BEGIN{print (last >= 0.9*total) ? "OK" : "FAIL"}')
    fi

    if [ "$reached" != "OK" ]; then
        ALL_OK=0
    fi

    echo "  DONE  pct=${pct}%  wall=${wall}s  last_t=${last_t}s  beacon_rows=${beacon_rows}  uniq_ids=${uniq_ids}  reached_end=${reached}"
    SUMMARY_ROWS+=("${pct} ${rc} ${reached} ${last_t} ${beacon_rows} ${uniq_ids} ${wall}")
done

echo ""
echo "================= SUMMARY ================="
printf "%4s %3s %11s %8s %11s %8s %7s\n" "pct" "rc" "reached_end" "last_t" "beacon_rows" "uniq_ids" "wall_s"
for row in "${SUMMARY_ROWS[@]}"; do
    printf "%4s %3s %11s %8s %11s %8s %7s\n" $row
done
echo "============================================="

if [ "$ALL_OK" -ne 1 ]; then
    echo ""
    echo "One or more smoke runs FAILED or did not reach the end of phase 6."
    echo "Do NOT proceed to the full 288s sweep until this is fixed — check the"
    echo "per-run run.log files under: $DS_REL/pct<PCT>_smoke_s${SEED}/run.log"
    exit 1
fi

echo ""
echo "All smoke runs OK. Dataset root: $DS_REL"
echo "Safe to proceed to the full sweep (dataset_sweep_seq6_pct.sh) with matching flags."
