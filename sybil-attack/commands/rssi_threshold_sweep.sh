#!/bin/bash
# =============================================================================
# rssi_threshold_sweep.sh — Attack percentage sweep with fixed best parameters
#
# Sweeps sybil_attack_percentage across all attack types.
# Detector parameters fixed to best values found during tuning.
#
# Parameters swept:
#   attack_type       : 2 3 4
#   attack_percentage : 0 20 40 60 80 100
#   Total runs        : 3 × 6 = 18
#
# Usage:
#   cd /root/FYP/ns-allinone-3.35/ns-3.35
#   bash sybil-attack/commands/rssi_threshold_sweep.sh
# =============================================================================

SIM_DIR="/root/FYP/ns-allinone-3.35/ns-3.35"
OUT_DIR="$SIM_DIR/sybil-attack/outputs"
METRICS_CSV="$OUT_DIR/rssi_percentage_sweep.csv"
TMP_DIR="$OUT_DIR/rssi_pct_tmp"

N_PARALLEL=4

ATTACK_TYPES="2 3 4"
ATTACK_PERCENTAGES="0 20 40 60 80 100"

# ── Fixed detector settings (best found) ──────────────────────────────────────
SIM_TIME=30
CLUSTER_R=1
DIST1_THRESH=1
STREAK=2
WINDOW=2.0
MIN_SAMPLES=8

mkdir -p "$OUT_DIR" "$TMP_DIR"
rm -f "$TMP_DIR"/*.csv

TOTAL_RUNS=$(( $(echo $ATTACK_TYPES | wc -w) * $(echo $ATTACK_PERCENTAGES | wc -w) ))
HEADER="attack_type,attack_pct,TP,FP,TN,FN,FPR,MDR,Precision,Recall,MCC"

echo "=============================================="
echo " RSSI Percentage Sweep  —  $(date)"
echo " Parallel jobs : $N_PARALLEL"
echo " Total runs    : $TOTAL_RUNS"
echo " SimTime       : ${SIM_TIME}s"
echo " cluster_r=${CLUSTER_R}m  dist1=${DIST1_THRESH}m  streak=${STREAK}  window=${WINDOW}s  min_samples=${MIN_SAMPLES}"
echo "=============================================="

# ── Worker function ────────────────────────────────────────────────────────────
run_one() {
    local atk=$1 pct=$2 run_num=$3

    local tag="atk${atk}_pct${pct}"
    local tmp="$TMP_DIR/${tag}.csv"

    echo "  START  run $run_num/$TOTAL_RUNS | atk=$atk  pct=${pct}%  $(date +%H:%M:%S)"

    # 0% = no attack — disable sybil entirely
    local atk_enabled="true"
    [ "$pct" -eq 0 ] && atk_enabled="false"

    local result
    result=$(cd "$SIM_DIR" && ./waf --run \
        "Sybil-Developing-Improved \
         --mobility_mode=5 --solution_mode=2 --routing_test=false \
         --sybil_attack_enabled=${atk_enabled} --sybil_attack_type=${atk} \
         --sybil_attack_percentage=${pct} --simTime=${SIM_TIME} --beaconInterval=0.1 \
         --sumoAutoConfig=true \
         --rssiWindowSec=${WINDOW} --rssiMinSamples=${MIN_SAMPLES} \
         --rssiDist1Thresh=${DIST1_THRESH} \
         --rssiClusterRadius=${CLUSTER_R} --rssiStreak=${STREAK} \
         --sweepMode=true" 2>&1 \
        | grep "\[RSSI_RESULT\]")

    if [ -z "$result" ]; then
        echo "  CRASH  run $run_num/$TOTAL_RUNS | atk=$atk  pct=${pct}%"
        echo "${atk},${pct},CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED,CRASHED" > "$tmp"
        return 1
    fi

    local TP FP TN FN FPR MDR PRE REC MCC
    TP=$(echo "$result"  | grep -oP  'TP=\K[0-9]+')
    FP=$(echo "$result"  | grep -oP  'FP=\K[0-9]+')
    TN=$(echo "$result"  | grep -oP  'TN=\K[0-9]+')
    FN=$(echo "$result"  | grep -oP  'FN=\K[0-9]+')
    FPR=$(echo "$result" | grep -oP 'FPR=\K[-0-9.nan]+')
    MDR=$(echo "$result" | grep -oP 'MDR=\K[-0-9.nan]+')
    PRE=$(echo "$result" | grep -oP 'Pre=\K[-0-9.nan]+')
    REC=$(echo "$result" | grep -oP 'Rec=\K[-0-9.nan]+')
    MCC=$(echo "$result" | grep -oP 'MCC=\K[-0-9.nan]+')

    echo "${atk},${pct},${TP},${FP},${TN},${FN},${FPR},${MDR},${PRE},${REC},${MCC}" > "$tmp"
    echo "  DONE   run $run_num/$TOTAL_RUNS | atk=$atk  pct=${pct}%  MCC=$MCC  FPR=$FPR  $(date +%H:%M:%S)"
}

# ── Launch jobs with N_PARALLEL concurrency ────────────────────────────────────
run_num=0
for atk in $ATTACK_TYPES; do
    for pct in $ATTACK_PERCENTAGES; do
        run_num=$(( run_num + 1 ))
        while [ "$(jobs -rp | wc -l)" -ge "$N_PARALLEL" ]; do
            sleep 3
        done
        run_one "$atk" "$pct" "$run_num" &
    done
done

echo ""
echo "All jobs launched — waiting for completion..."
wait
echo "All jobs finished — $(date)"

# ── Merge results in order ─────────────────────────────────────────────────────
echo "$HEADER" > "$METRICS_CSV"
for atk in $ATTACK_TYPES; do
    for pct in $ATTACK_PERCENTAGES; do
        local_csv="$TMP_DIR/atk${atk}_pct${pct}.csv"
        [ -f "$local_csv" ] && cat "$local_csv" >> "$METRICS_CSV"
    done
done

rm -rf "$TMP_DIR"

echo ""
echo "=============================================="
echo " SWEEP COMPLETE — $(date)"
echo " Results : $METRICS_CSV"
echo "=============================================="
echo ""
cat "$METRICS_CSV"
echo ""
echo "Run the grapher:"
echo "  python3 sybil-attack/scripts/plot_rssi_results.py"
