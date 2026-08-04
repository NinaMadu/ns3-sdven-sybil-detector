#!/bin/bash
# lw_ttl_sweep.sh — sliding-window (lwFlagTtlSec) sweep for the lightweight tier.
# label:gate:mask:ttl   mask 4294967295=all, 80=trajectory|temporal
set -uo pipefail
SIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PCT=${PCT:-40}; SEED=${SEED:-1}; TOTAL=${TOTAL_SIM_TIME:-180}; JOBS=${JOBS:-6}
SIM_TIME=$(awk -v t="$TOTAL" 'BEGIN{printf "%.6f", t/6}')
DS_REL="sybil-attack/datasets/${OUT_NAME:-lw_ttl_sweep}"
BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
ARMS=("all_ttl3:0:4294967295:3" "traj_temporal_ttl3:0:80:3" "minus_coloc_ttl3:0:4294967263:3" "minus_mm_ttl3:0:4294967039:3" "ref_ttl3:1:4294967295:3" "all_ttl0:0:4294967295:0")
      "all_ttl0:0:4294967295:0" "all_ttl5:0:4294967295:5"
n=0
for arm in "${ARMS[@]}"; do
  IFS=: read -r label gate mask ttl <<< "$arm"
  rel="${DS_REL}/${label}"; mkdir -p "$SIM_DIR/$rel"
  ( cd "$SIM_DIR" && "$BIN" --mobility_mode=5 --routing_test=false --sumoAutoConfig=false \
      --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
      --mobilityMode5TraceFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_mobility.tcl \
      --mobilityMode5RsuPositionFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_rsus_8x8.csv \
      --sybil_attack_enabled=true --datasetMode=sequential_all6 --solution_mode=4 \
      --sybil_attack_percentage=${PCT} --simTime=${SIM_TIME} --beaconInterval=0.1 \
      --intensitySchedule=stepped --sybilFanoutRange=2,20 --ipfsPublish=false \
      --seed=${SEED} --lwScoringMode=1 --lwOracleGate=${gate} --lwCoLocMinObservers=3 \
      --lwSsdSignatureMask=${mask} --lwFlagTtlSec=${ttl} \
      --runId=${label} --outputDir=${rel} --quietMode=true ) > "$SIM_DIR/$rel/run.log" 2>&1 &
  n=$((n+1)); [ "$n" -ge "$JOBS" ] && { wait -n 2>/dev/null || wait; n=$((n-1)); }
done
wait
echo "=============================================================="
echo " LW-SSD SLIDING WINDOW SWEEP — identity grain (${TOTAL}s, ${PCT}%)"
echo "=============================================================="
printf '  %-12s %5s %5s %5s %5s %8s %8s %8s\n' arm TP FP FN TN MCC Prec Recall
for arm in "${ARMS[@]}"; do
  l="${arm%%:*}"; f="$SIM_DIR/$DS_REL/$l/metrics_M5_M6_identity.csv"
  [ -f "$f" ] && awk -F, -v l="$l" 'NR==2{printf "  %-12s %5d %5d %5d %5d %8.4f %8.4f %8.4f\n",l,$2,$3,$4,$5,$6,$7,$8}' "$f"
done
echo "Dataset: $DS_REL"
