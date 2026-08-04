#!/usr/bin/env bash
# Step 1 of the Lambda modeling-update response: measure the EMPIRICAL Lambda(t)
# distribution under the fixed windowed-Lambda definition, so the engage /
# disengage thresholds in the parameters table can be calibrated against real
# numbers instead of the current hand-picked defaults.
#
# Lambda(t) = |flagged in last W s| / |observed in last W s|, logged every
# --modeSelectInterval seconds into mode_selector_log.csv REGARDLESS of whether a
# switch happens -- so one run per condition yields the whole trace.
#
# Lambda's scale differs between the two modes (the suspicion flags computed
# under M_L and M_F are not the same set), and each side calibrates a different
# threshold, so both are measured:
#
#   engage arm  (lo20/lo40/lo60): lambdaHi=1.0 -> selector can never engage
#                (needs ALL observed ids flagged), so the run stays LIGHTWEIGHT
#                and the trace is the M_L-side Lambda that Lambda_hi is compared
#                against when deciding to ESCALATE.
#   disengage arm (hi40):         lambdaLo=0.0, lambdaHi=0.001 -> engages on the
#                first flag and can never fall below 0.0, so the run locks into
#                FULL and the trace is the M_F-side Lambda that Lambda_lo is
#                compared against when deciding to DE-escalate.
#
# NOTE the CLI clamps both thresholds into [0,1] and force-raises lambdaHi if it
# is <= lambdaLo, which is why the bounds above are 1.0 / 0.001 rather than
# 2.0 / 0.0.
set -uo pipefail
cd /home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35

SIMT=40
COMMON="--solution_mode=7 --simTime=$SIMT --routing_test=false --sumoAutoConfig=false \
 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_mode=5 \
 --mobilityTraceFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_mobility.tcl \
 --mobilityRsuPositionFile=sybil-attack/inputs/mobility/kuala-lumpur-bb/klbb2km_rsus_8x8.csv \
 --sybil_attack_enabled=true --sybil_attack_type=2 --sybil_attacker_level=2 \
 --beaconInterval=0.1 --detectLatency=0.05 --full_crypto_profile=2 \
 --ipfsPublish=false --rsuRevocationThreshold=3 --seed=42 \
 --beaconChannelMode=2 --evidenceJsonFiles=false --quietMode=true \
 --lambdaWindow=10 --modeDwell=5 --modeSelectInterval=1.0"

run () {                       # $1=tag  $2=attacker%  $3=extra flags
  local O=sybil-attack/datasets/a1lambda_$1
  rm -rf "$O"; mkdir -p "$O"
  /usr/bin/time -v ./waf --run "Sybil-Developing-Improved $COMMON \
    --sybil_attack_percentage=$2 $3 --outputDir=$O" > "$O/sim_stdout.log" 2>&1
  echo "$?" > "$O/.exit_code"
}

# engage-side: stays LIGHTWEIGHT, sweep attacker penetration
run lo20 20 "--lambdaHi=1.0" &
run lo40 40 "--lambdaHi=1.0" &
run lo60 60 "--lambdaHi=1.0" &
# disengage-side: locks into FULL at the reference 40%
run hi40 40 "--lambdaLo=0.0 --lambdaHi=0.001" &
wait
touch sybil-attack/datasets/.a1lambda_done
echo "ALL DONE"
