
#!/bin/bash
# =============================================================================
# type2_pct_sweep_mode4.sh — attacker-percentage sweep for attack type 2
# (Insider Direct Simultaneous) under solution_mode=4 (MODE_LIGHTWEIGHT).
#
# Mode-4 twin of type2_pct_sweep_mode5.sh: every flag is identical except
# --solution_mode and the full-mode-only knobs (--llmDetectInterval), so the
# two sweeps are directly comparable arm-for-arm.
#
# Why not sequential_all6 (as in dataset_sweep_seq6_pct_smoke.sh): this sweeps
# ONE attack type, so --datasetMode is omitted and --sybil_attack_type=2 drives
# the legacy per-type scheduler (sybil_attacks.h case
# ATTACK_INSIDER_DIRECT_SIMULTANEOUS). Consequences:
#   * --intensitySchedule is a no-op off the seq6 path — attacker % stays flat
#     per run, which is what a percentage sweep wants.
#   * --sybilFanoutRange is ALSO a no-op there; identity count comes from
#     SimultaneousSybilBudget(). Use --sybilIdentitiesPerAttacker to override.
#
# --simTime=30 is the TOTAL run length (not per-phase) and is safely above the
# 12 s sumoAutoConfig trace-stretch threshold.
#
# --lwOracleGate defaults to 1 (published LW-SSD behaviour, the C++ default).
# Set LW_ORACLE_GATE=0 for the oracle-free arm; M5-M8 are then NOT comparable
# with gate=1 runs.
#
# Usage:
#   bash sybil-attack/commands/type2_pct_sweep_mode4.sh
#   PCTS="20 40" bash sybil-attack/commands/type2_pct_sweep_mode4.sh
#   LW_ORACLE_GATE=0 bash sybil-attack/commands/type2_pct_sweep_mode4.sh
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCTS=${PCTS:-"20 40 60 80 100"}
SEED=${SEED:-1}
SIM_TIME=${SIM_TIME:-30}
LW_ORACLE_GATE=${LW_ORACLE_GATE:-1}

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_NAME=${OUT_NAME:-"type2_mode4_sweep_${STAMP}"}
DS_REL="sybil-attack/datasets/${OUT_NAME}"
DS_ABS="$SIM_DIR/$DS_REL"
mkdir -p "$DS_ABS"

SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — aborting."; exit 1; }

echo "=========================================================="
echo " Type-2 x attacker-% sweep, MODE_LIGHTWEIGHT (solution_mode=4)"
echo " Percentages : $PCTS"
echo " Seed        : $SEED"
echo " simTime     : ${SIM_TIME}s   lwOracleGate: ${LW_ORACLE_GATE}"
echo " Dataset root: $DS_REL"
echo " Started     : $(date)"
echo "=========================================================="

SUMMARY_ROWS=()

for pct in $PCTS; do
    run_id="pct${pct}_s${SEED}"
    run_rel="${DS_REL}/${run_id}"
    run_abs="$SIM_DIR/$run_rel"
    mkdir -p "$run_abs"

    echo "  START pct=${pct}%  $(date +%H:%M:%S)"
    t0=$(date +%s)

    ( cd "$SIM_DIR" && "$SIM_BIN" \
        --mobility_mode=5 \
        --routing_test=false \
        --sumoAutoConfig=true \
        --sybil_attack_enabled=true \
        --sybil_attack_type=2 \
        --solution_mode=4 \
        --sybil_attack_percentage=${pct} \
        --simTime=${SIM_TIME} \
        --beaconInterval=0.1 \
        --lwOracleGate=${LW_ORACLE_GATE} \
        --ipfsPublish=false \
        --seed=${SEED} \
        --runId=${run_id} \
        --outputDir=${run_rel} \
        --quietMode=false ) > "$run_abs/run.log" 2>&1
    rc=$?
    t1=$(date +%s)
    wall=$(( t1 - t0 ))

    last_t="-"; mcc="-"; recall="-"; prec="-"
    beacon_csv="$run_abs/communication_log.csv"
    [ -f "$beacon_csv" ] && last_t=$(awk -F, 'NR>1{t=$1} END{print t+0}' "$beacon_csv")

    # CUMULATIVE row of the M5/M6 matrix: MCC=$7 Precision=$9 Recall=$10
    q_csv="$run_abs/metrics_M5_M6_detection_quality.csv"
    if [ -f "$q_csv" ]; then
        read -r mcc prec recall <<<"$(awk -F, '$2=="CUMULATIVE"{print $7, $9, $10}' "$q_csv" | head -1)"
        mcc=${mcc:-"-"}; prec=${prec:-"-"}; recall=${recall:-"-"}
    fi

    if [ $rc -ne 0 ]; then
        echo "  CRASH pct=${pct}%  rc=${rc}  wall=${wall}s"
    else
        echo "  DONE  pct=${pct}%  wall=${wall}s  last_t=${last_t}  MCC=${mcc}  P=${prec}  R=${recall}"
    fi
    SUMMARY_ROWS+=("${pct} ${rc} ${wall} ${last_t} ${mcc} ${prec} ${recall}")
done

echo ""
echo "===================== SUMMARY ====================="
printf "%5s %3s %7s %8s %10s %10s %10s\n" "pct" "rc" "wall_s" "last_t" "MCC" "Precision" "Recall"
for row in "${SUMMARY_ROWS[@]}"; do
    printf "%5s %3s %7s %8s %10s %10s %10s\n" $row
done
echo "==================================================="
echo "Dataset root: $DS_REL"
echo "Finished: $(date)"
