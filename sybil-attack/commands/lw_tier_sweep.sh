#!/bin/bash
set -uo pipefail
SIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PCT=${PCT:-40}; TOTAL=${TOTAL_SIM_TIME:-180}; SIM_TIME=$(awk -v t="$TOTAL" 'BEGIN{printf "%.6f",t/6}')
DS_REL="sybil-attack/datasets/${OUT_NAME:-lw_tier_sweep}"
BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
# label:gate:mask:ttl:minconfirm
ARMS=("tier_off:0:4294967263:3:1" "tier2:0:4294967263:3:2" "tier3:0:4294967263:3:3"
      "tier2_allmask:0:4294967295:3:2" "tier3_allmask:0:4294967295:3:3" "ref:1:4294967295:3:1")
n=0
for arm in "${ARMS[@]}"; do
  IFS=: read -r l g m t c <<< "$arm"; rel="${DS_REL}/${l}"; mkdir -p "$SIM_DIR/$rel"
  ( cd "$SIM_DIR" && "$BIN" --mobility_mode=5 --routing_test=false --sumoAutoConfig=false \
      --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
      --mobilityMode5TraceFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_mobility.tcl \
      --mobilityMode5RsuPositionFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_rsus_8x8.csv \
      --sybil_attack_enabled=true --datasetMode=sequential_all6 --solution_mode=4 \
      --sybil_attack_percentage=${PCT} --simTime=${SIM_TIME} --beaconInterval=0.1 \
      --intensitySchedule=stepped --sybilFanoutRange=2,20 --ipfsPublish=false --seed=1 \
      --lwScoringMode=1 --lwOracleGate=${g} --lwCoLocMinObservers=3 --lwSsdSignatureMask=${m} \
      --lwFlagTtlSec=${t} --lwTierBMinConfirm=${c} \
      --runId=${l} --outputDir=${rel} --quietMode=true ) > "$SIM_DIR/$rel/run.log" 2>&1 &
  n=$((n+1)); [ "$n" -ge 6 ] && { wait -n 2>/dev/null || wait; n=$((n-1)); }
done
wait; echo ALLDONE
