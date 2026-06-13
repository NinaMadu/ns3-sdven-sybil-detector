#!/usr/bin/env bash
# =============================================================================
# run_solution_mode2_sweep.sh
#
# Sweeps the Sybil detection solution (solution_mode=2) over:
#   attack types         : 1 2 3 4 5
#   attack percentages   : 0 20 40 60 80 100
# on mobility_mode=5 (SUMO Kuala Lumpur BB).  That is 5 x 6 = 30 runs.
#
# For every run it reads the RSSI detector's final confusion matrix — the
# '#SUMMARY' line in sybil-attack/outputs/rssi_paper_detection_log.csv
# (this is solution_mode=2's own detector, NOT the packet-level M5_M6 file) —
# recomputes MCC / FPR / Precision / Recall, and appends one row to:
#       <results_dir>/solution_mode_2_results.csv
#
# Finally it calls plot_solution_mode2.py to render four graphs
# (MCC, Recall, Precision, FPR vs attack percentage, one line per attack type).
#
# Usage (from anywhere):
#   bash sybil-attack/configs/run_solution_mode2_sweep.sh
# Optional overrides via env vars:
#   SIM_TIME=60 BEACON=0.1 TYPES="1 2 3 4 5" PCTS="0 20 40 60 80 100" \
#       bash sybil-attack/configs/run_solution_mode2_sweep.sh
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Walk up to the ns-3.35 root (the directory that contains 'waf').
NS3_ROOT="$SCRIPT_DIR"
while [ ! -f "$NS3_ROOT/waf" ] && [ "$NS3_ROOT" != "/" ]; do
    NS3_ROOT="$(dirname "$NS3_ROOT")"
done
[ -f "$NS3_ROOT/waf" ] || { echo "ERROR: could not find ns-3.35 root (no waf)"; exit 1; }
cd "$NS3_ROOT"

# ---- sweep parameters (override via env) ------------------------------------
TYPES=(${TYPES:-1 2 3 4 5})
PCTS=(${PCTS:-0 20 40 60 80 100})
SIM_TIME="${SIM_TIME:-60}"
BEACON="${BEACON:-0.1}"
MOBILITY_MODE=5
SOLUTION_MODE=2

STAMP="$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="sybil-attack/configs/solution_mode2_${STAMP}"
RESULTS_CSV="${RESULTS_DIR}/solution_mode_2_results.csv"
# solution_mode=2 is the RSSI detector; its final confusion matrix is the
# '#SUMMARY' line appended to this log (rssi_sybil_detection.h::PrintMetrics).
OUT_CSV="sybil-attack/outputs/rssi_paper_detection_log.csv"
EXTRACT_PY="${SCRIPT_DIR}/plot_solution_mode2.py"

mkdir -p "$RESULTS_DIR"
# CSV header
echo "attack_type,attack_percentage,TP,FP,FN,TN,MCC,FPR,Precision,Recall" > "$RESULTS_CSV"

echo "=== Building Sybil-Developing-Improved ==="
./waf build || { echo "build failed"; exit 1; }

run_count=0
total=$(( ${#TYPES[@]} * ${#PCTS[@]} ))

for T in "${TYPES[@]}"; do
  for P in "${PCTS[@]}"; do
    run_count=$((run_count + 1))
    LOGDIR="${RESULTS_DIR}/type${T}_pct${P}"
    mkdir -p "$LOGDIR"
    echo
    echo "=== [${run_count}/${total}] attack_type=${T}  attack_percentage=${P}% ==="

    rm -f sybil-attack/outputs/*.csv   # isolate this run's outputs

    ./waf --run "Sybil-Developing-Improved \
        --mobility_mode=${MOBILITY_MODE} \
        --solution_mode=${SOLUTION_MODE} \
        --routing_test=false \
        --sybil_attack_enabled=true \
        --sybil_attack_type=${T} \
        --sybil_attack_percentage=${P} \
        --simTime=${SIM_TIME} \
        --beaconInterval=${BEACON}" 2>&1 | tee "${LOGDIR}/run.log"

    # archive this run's RSSI detection log for traceability
    cp "$OUT_CSV" "${LOGDIR}/rssi_paper_detection_log.csv" 2>/dev/null || true

    # pool the confusion matrix and append one row to the results CSV
    python3 "$EXTRACT_PY" extract \
        --detection-csv "$OUT_CSV" \
        --attack-type "$T" \
        --attack-percentage "$P" \
        --out-csv "$RESULTS_CSV"
  done
done

echo
echo "=== Sweep complete. Results CSV -> ${NS3_ROOT}/${RESULTS_CSV} ==="

echo "=== Plotting MCC / Recall / Precision / FPR ==="
python3 "$EXTRACT_PY" plot \
    --results-csv "$RESULTS_CSV" \
    --out-dir "$RESULTS_DIR"

echo
echo "=== DONE ==="
echo "Results : ${NS3_ROOT}/${RESULTS_CSV}"
echo "Plots   : ${NS3_ROOT}/${RESULTS_DIR}/*.png"
ls -1 "${RESULTS_DIR}"/*.png 2>/dev/null
