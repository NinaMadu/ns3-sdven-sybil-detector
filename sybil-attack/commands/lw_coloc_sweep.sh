#!/bin/bash
# =============================================================================
# lw_coloc_sweep.sh — Eq 3.6 parameter sweep for the ORACLE-FREE lightweight tier.
#
# Follows lw_oracle_gate_ab.sh, which established that:
#   * D_LW's detection is real once the vehicle tier is wired in (identity
#     precision 0.805 / recall 0.805 oracle-free), and
#   * its remaining false positives come almost entirely from RSSI co-location
#     (45 of 59 false-positive identities) plus rssi_distance_mismatch (14 of 59,
#     at precision 0.000 — it flags legitimate vehicles only).
#
# Two levers are swept here:
#   lwCoLocMinObservers  how many observers must agree before a pair is flagged.
#                        At the 20 ms window typically only ~2 observers see both
#                        identities of a pair, so the report's "for all k in O" has
#                        almost nothing to quantify over and barely filters.
#   lwCoLocWindowSec     widening the coincidence window enlarges O per pair, which
#                        is what gives the for-all quantifier force.
# plus lwSsdDropRssiDistMismatch, to remove the known pure-FP signature.
#
# All arms are solution_mode=4 with no LLM daemon, so they parallelise safely
# (the daemon socket collision applies only to full/adaptive mode).
#
# Usage:  bash sybil-attack/commands/lw_coloc_sweep.sh
#         PCT=40 TOTAL_SIM_TIME=36 JOBS=5 bash sybil-attack/commands/lw_coloc_sweep.sh
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCT=${PCT:-40}
SEED=${SEED:-1}
TOTAL_SIM_TIME=${TOTAL_SIM_TIME:-36}
JOBS=${JOBS:-5}
N_PHASES=6
SIM_TIME=$(awk -v t="$TOTAL_SIM_TIME" -v n="$N_PHASES" 'BEGIN{printf "%.6f", t/n}')

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_NAME=${OUT_NAME:-"lw_coloc_sweep_${STAMP}"}
DS_REL="sybil-attack/datasets/${OUT_NAME}"
mkdir -p "$SIM_DIR/$DS_REL"

SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — run ./waf build first."; exit 1; }

# label:gate:minObs:windowSec:dropMismatch
ARMS=(
  "ref_oracle:1:2:0.020:0"
  "base_minobs2:0:2:0.020:0"
  "minobs3:0:3:0.020:0"
  "minobs4:0:4:0.020:0"
  "minobs5:0:5:0.020:0"
  "minobs3_win50:0:3:0.050:0"
  "minobs3_win100:0:3:0.100:0"
  "dropmm_only:0:2:0.020:1"
  "minobs3_win50_dropmm:0:3:0.050:1"
)

echo "=========================================================="
echo " Eq 3.6 co-location sweep — $(date)"
echo " attackers=${PCT}%  seed=${SEED}  ${SIM_TIME}s/phase (${TOTAL_SIM_TIME}s total)"
echo " arms=${#ARMS[@]}  parallelism=${JOBS}"
echo " dataset root: $DS_REL"
echo "=========================================================="

run_arm () {
    IFS=: read -r label gate minobs win dropmm <<< "$1"
    local run_rel="${DS_REL}/${label}"
    mkdir -p "$SIM_DIR/$run_rel"
    ( cd "$SIM_DIR" && "$SIM_BIN" \
        --mobility_mode=5 --routing_test=false --sumoAutoConfig=true \
        --sybil_attack_enabled=true --datasetMode=sequential_all6 \
        --solution_mode=4 --sybil_attack_percentage=${PCT} \
        --simTime=${SIM_TIME} --beaconInterval=0.1 \
        --intensitySchedule=stepped --sybilFanoutRange=2,20 \
        --ipfsPublish=false --seed=${SEED} \
        --lwScoringMode=1 \
        --lwOracleGate=${gate} \
        --lwCoLocMinObservers=${minobs} \
        --lwCoLocWindowSec=${win} \
        --lwSsdDropRssiDistMismatch=${dropmm} \
        --runId=${label} --outputDir=${run_rel} \
        --quietMode=true ) > "$SIM_DIR/$run_rel/run.log" 2>&1
    echo "  done: ${label} (rc=$?)"
}

t0=$(date +%s)
running=0
for arm in "${ARMS[@]}"; do
    run_arm "$arm" &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
done
wait
t1=$(date +%s)
echo "  all arms complete in $(( t1 - t0 ))s"

echo
echo "=================================================================================="
echo " IDENTITY-LEVEL MATRIX  (the unit D_LW actually decides in)"
echo "=================================================================================="
printf '  %-22s %5s %5s %5s %5s  %8s %8s %8s %8s\n' \
       arm TP FP FN TN MCC Prec Recall FPR
for arm in "${ARMS[@]}"; do
    label="${arm%%:*}"
    f="$SIM_DIR/$DS_REL/$label/metrics_M5_M6_identity.csv"
    if [ -f "$f" ]; then
        awk -F, -v l="$label" 'NR==2{printf "  %-22s %5d %5d %5d %5d  %8.4f %8.4f %8.4f %8.4f\n",
                                     l,$2,$3,$4,$5,$6,$7,$8,$9}' "$f"
    else
        printf '  %-22s (no output)\n' "$label"
    fi
done

echo
echo "=================================================================================="
echo " PACKET-LEVEL MATRIX  (M5/M6 as currently reported)"
echo "=================================================================================="
printf '  %-22s %8s %8s %8s\n' arm MCC Prec Recall
for arm in "${ARMS[@]}"; do
    label="${arm%%:*}"
    f="$SIM_DIR/$DS_REL/$label/metrics_M5_M6_detection_quality.csv"
    if [ -f "$f" ]; then
        grep CUMULATIVE_BY_SOURCE "$f" | tail -1 | \
          awk -F, -v l="$label" '{printf "  %-22s %8.4f %8.4f %8.4f\n",l,$7,$9,$10}'
    fi
done

echo
echo "=================================================================================="
echo " CO-LOCATION SIGNATURE ONLY (identity unit) — is the for-all quantifier working?"
echo "=================================================================================="
printf '  %-22s %10s %8s %8s %10s\n' arm flagged sybil legit precision
for arm in "${ARMS[@]}"; do
    label="${arm%%:*}"
    f="$SIM_DIR/$DS_REL/$label/lwssd_flag_attribution.csv"
    [ -f "$f" ] && awk -F, -v l="$label" '$1=="rssi_colocation"{
        printf "  %-22s %10d %8d %8d %10.4f\n",l,$2,$3,$4,$5}' "$f"
done

echo
echo "Dataset: $DS_REL"
