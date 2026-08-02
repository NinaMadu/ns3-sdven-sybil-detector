#!/bin/bash
# ---------------------------------------------------------------------------
# Three-arm security overhead comparison: none vs classical vs post-quantum.
# See sybil-attack/docs/PQC_vs_Classical_Comparison_README.md
#
#   bash sybil-attack/commands/run_suite_comparison.sh
#   SEEDS="1 2 3" SIMTIME=60 bash sybil-attack/commands/run_suite_comparison.sh
#   ARMS="classical pqc" bash ...      # skip the plain-network arm
#
# Arms run SEQUENTIALLY on purpose: the crypto timings are wall-clock, and two
# simulations competing for CPU corrupt every one of them.
# ---------------------------------------------------------------------------
set -u

cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35

SEEDS=${SEEDS:-"1 2 3"}
ARMS=${ARMS:-"none classical pqc"}
SIMTIME=${SIMTIME:-60}
NVEH=${NVEH:-200}
NRSU=${NRSU:-64}
ATTACK_TYPE=${ATTACK_TYPE:-2}
ATTACK_PCT=${ATTACK_PCT:-30}
BASE=${BASE:-sybil-attack/datasets/suite_cmp}

mkdir -p "$BASE"

run_arm () {   # $1=arm  $2=attack(true|false)  $3=pct  $4=seed
  local arm=$1 attack=$2 pct=$3 seed=$4 sec out

  case "$arm" in
    none)      sec="--SecEnabled=false --solution_mode=5" ;;
    classical) sec="--solution_mode=5 --full_crypto_profile=1" ;;
    pqc)       sec="--solution_mode=5 --full_crypto_profile=2" ;;
    *) echo "unknown arm '$arm'" >&2; return 1 ;;
  esac

  out="$BASE/${arm}_atk${attack}_pct${pct}_s${seed}"
  if [ -f "$out/metrics_S_security_profile.csv" ]; then
    echo "[skip] $out already complete"
    return 0
  fi
  mkdir -p "$out"

  echo "[$(date +%H:%M:%S)] running $out"
  ./waf --run "Sybil-Developing-Improved \
    $sec \
    --routing_test=false \
    --ipfsPublish=false \
    --mobility_mode=5 \
    --sumoAutoConfig=false \
    --N_Vehicles=$NVEH --N_RSUs=$NRSU --N_Controllers=4 \
    --sybil_attack_enabled=$attack \
    --sybil_attack_type=$ATTACK_TYPE \
    --sybil_attack_percentage=$pct \
    --beaconInterval=0.1 \
    --simTime=$SIMTIME \
    --RngRun=$seed \
    --outputDir=$out" > "$out/run.log" 2>&1
  local rc=$?

  if [ $rc -ne 0 ]; then
    echo "  !! FAILED rc=$rc — see $out/run.log" >&2
    tail -5 "$out/run.log" >&2
    return 0                      # keep the campaign going
  fi

  grep -m1 '^\[SecuritySuite\] arm' "$out/run.log" | sed 's/^/  /'
  grep -m1 'FATAL-ish' "$out/run.log" >&2

  # Topology sanity: with N_RSUs too small no handshake ever completes and the
  # whole security layer sits idle, which looks like "crypto is free".
  local ch
  ch=$(grep -c "secure channel established" "$out/run.log")
  echo "  secure channels established: $ch"
  [ "$ch" -eq 0 ] && echo "  !! WARNING: no secure channel established — check topology" >&2

  return 0
}

echo "arms=[$ARMS]  seeds=[$SEEDS]  simTime=${SIMTIME}s  ${NVEH}veh/${NRSU}rsu"
echo "output -> $BASE"
echo

for seed in $SEEDS; do
  for arm in $ARMS; do
    run_arm "$arm" false 0            "$seed"
    run_arm "$arm" true  $ATTACK_PCT  "$seed"
  done
done

echo
echo "=== done — building comparison tables ==="
python3 sybil-attack/commands/compare_security_suites.py "$BASE" \
        --csv-out "$BASE/_tables"
