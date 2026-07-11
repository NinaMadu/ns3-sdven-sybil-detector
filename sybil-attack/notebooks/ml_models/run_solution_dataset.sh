#!/usr/bin/env bash
# =============================================================================
# run_solution_dataset.sh — generate the DATASET for our own solution
# (temporal + RSSI + trust-score analyzers).
#
# Runs 5 scenarios with SUMO Kuala Lumpur mobility (mobility_mode=5) at 20%
# attackers: clean baseline + all four Sybil attack types. Each run is archived
# with ALL its CSV outputs, so both data sources are captured per scenario:
#   communication_log.csv      -> temporal analyzer features
#   rssi_verification_log.csv   -> RSSI analyzer features
#
# Usage (from anywhere):  bash sybil-attack/ml-baseline/run_solution_dataset.sh
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

STAMP="$(date +%Y%m%d_%H%M%S)"
DATASET_ROOT="sybil-attack/datasets/solution_ds_${STAMP}"
# baseline = no attack; the four attack configs are already 20% attackers.
SCENARIOS=("baseline" "sybil_type1" "sybil_type2" "sybil_type3" "sybil_type4")

echo "=== Building Sybil-Developing-Improved ==="
./waf build || { echo "build failed"; exit 1; }
mkdir -p "$DATASET_ROOT"

for SC in "${SCENARIOS[@]}"; do
  CFG="sybil-attack/configs/ds_${SC}.cfg"
  OUTDIR="${DATASET_ROOT}/${SC}"
  echo
  echo "=== Scenario: ${SC}  (config=${CFG}, SUMO-KL, 20% attackers) ==="
  mkdir -p "$OUTDIR"
  rm -f sybil-attack/outputs/*.csv               # only archive THIS run's files
  ./waf --run "Sybil-Developing-Improved --config=${CFG}" 2>&1 | tee "${OUTDIR}/run.log"
  cp sybil-attack/outputs/*.csv "$OUTDIR"/ 2>/dev/null || true
  cp "$CFG" "$OUTDIR"/scenario.cfg
  echo "--- archived $(ls -1 "$OUTDIR"/*.csv 2>/dev/null | wc -l) CSV(s) -> ${OUTDIR}"
done

echo
echo "=== DONE. Solution dataset -> ${NS3_ROOT}/${DATASET_ROOT} ==="
echo "Each scenario folder has communication_log.csv (temporal) +"
echo "rssi_verification_log.csv (RSSI)."
ls -1 "$DATASET_ROOT"
