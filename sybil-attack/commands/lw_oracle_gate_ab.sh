#!/bin/bash
# =============================================================================
# lw_oracle_gate_ab.sh — A/B the lightweight tier's ground-truth oracle.
#
# Runs MODE_LIGHTWEIGHT (solution_mode=4) twice on an identical environment,
# changing exactly one flag:
#
#   arm A  --lwOracleGate=1   published behaviour: D_LW may use the identity-range
#                             test claimedId >= N_Vehicles as its S^(out) stand-in.
#   arm B  --lwOracleGate=0   oracle-free: that test is dropped and D_LW scores the
#                             behavioural bank alone.
#
# Two things are being checked:
#   1. HONEST NUMBER — how well the lightweight rules actually separate Sybil from
#      legitimate identities once the label is no longer an input (metrics_M5_M6).
#   2. ISOLATION — every output that is NOT the scoring feed must be byte-identical
#      between the arms, which is what guarantees the trust / RSSI / temporal
#      analyzer inputs and MODE_FULL are untouched by this change.
#
# Environment matches commands/dataset_sweep_seq6_pct_smoke.sh so the run is
# comparable to the existing seq6 datasets. sequential_all6 walks attack types
# 1->6 in six back-to-back phases, so one run exercises every variant.
#
# Usage:
#   bash sybil-attack/commands/lw_oracle_gate_ab.sh
#   PCT=40 TOTAL_SIM_TIME=60 bash sybil-attack/commands/lw_oracle_gate_ab.sh
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCT=${PCT:-40}
SEED=${SEED:-1}
TOTAL_SIM_TIME=${TOTAL_SIM_TIME:-60}
N_PHASES=6
SIM_TIME=$(awk -v t="$TOTAL_SIM_TIME" -v n="$N_PHASES" 'BEGIN{printf "%.6f", t/n}')

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_NAME=${OUT_NAME:-"lw_oracle_ab_${STAMP}"}
DS_REL="sybil-attack/datasets/${OUT_NAME}"
mkdir -p "$SIM_DIR/$DS_REL"

SIM_BIN="$SIM_DIR/build/scratch/Sybil-Developing-Improved"
export LD_LIBRARY_PATH="$SIM_DIR/build/lib:$SIM_DIR/build:${LD_LIBRARY_PATH:-}"
[ -x "$SIM_BIN" ] || { echo "Binary not found at $SIM_BIN — run ./waf build first."; exit 1; }

echo "=========================================================="
echo " LW-SSD oracle A/B — $(date)"
echo " attackers=${PCT}%  seed=${SEED}  simTime/phase=${SIM_TIME}s (total ${TOTAL_SIM_TIME}s)"
echo " dataset root: $DS_REL"
echo "=========================================================="

run_arm () {
    local gate=$1
    local run_id="gate${gate}"
    local run_rel="${DS_REL}/${run_id}"
    mkdir -p "$SIM_DIR/$run_rel"

    echo "  START lwOracleGate=${gate}  $(date +%H:%M:%S)"
    local t0=$(date +%s)
    ( cd "$SIM_DIR" && "$SIM_BIN" \
        --mobility_mode=5 \
        --routing_test=false \
        --sumoAutoConfig=true \
        --sybil_attack_enabled=true \
        --datasetMode=sequential_all6 \
        --solution_mode=4 \
        --sybil_attack_percentage=${PCT} \
        --simTime=${SIM_TIME} \
        --beaconInterval=0.1 \
        --intensitySchedule=stepped \
        --sybilFanoutRange=2,20 \
        --ipfsPublish=false \
        --seed=${SEED} \
        --lwScoringMode=1 \
        --lwOracleGate=${gate} \
        --runId=${run_id} \
        --outputDir=${run_rel} \
        --quietMode=false ) > "$SIM_DIR/$run_rel/run.log" 2>&1
    local rc=$?
    local t1=$(date +%s)
    echo "  DONE  lwOracleGate=${gate}  rc=${rc}  wall=$(( t1 - t0 ))s"
    return $rc
}

run_arm 1 || { echo "arm A failed — see run.log"; exit 1; }
run_arm 0 || { echo "arm B failed — see run.log"; exit 1; }

A="$SIM_DIR/$DS_REL/gate1"
B="$SIM_DIR/$DS_REL/gate0"

echo
echo "=========================================================="
echo " ISOLATION CHECK — these must be IDENTICAL across the arms"
echo "=========================================================="
ISO_OK=1
# Two things legitimately differ between any two runs and are NOT behavioural:
#   * the run_id / outputDir label, which is embedded as a column in most logs;
#   * RSU signature columns — ECDSA and ML-DSA both use a random nonce, so the same
#     evidence signs to different bytes on every run, even run-to-run at fixed seed.
# Normalise both before comparing. The evidence log's evidenceVectorHashHex column is
# checked separately below and IS deterministic, so detection content is still verified.
norm () { sed -e 's/gate[01]/GATE/g' -e 's/current_[a-z_]*_rsu_[0-9]*:[0-9a-f]*/SIG/g' "$1"; }

for f in computed_detection_evidence_log.csv rssi_verification_log.csv \
         communication_log.csv vehicle_neighbor_table_log.csv \
         rsu_vehicle_table_log.csv rsu_regional_awareness_log.csv \
         controller_global_awareness_log.csv metrics_M1_PDR.csv \
         metrics_M3_PacketAttraction.csv; do
    if [ ! -f "$A/$f" ] || [ ! -f "$B/$f" ]; then
        printf '  %-42s SKIP (absent)\n' "$f"
        continue
    fi
    ha=$(norm "$A/$f" | md5sum | cut -d' ' -f1)
    hb=$(norm "$B/$f" | md5sum | cut -d' ' -f1)
    if [ "$ha" = "$hb" ]; then
        printf '  %-42s IDENTICAL\n' "$f"
    else
        printf '  %-42s ***DIFFERS***\n' "$f"
        diff <(norm "$A/$f") <(norm "$B/$f") | head -3 | sed 's/^/      /'
        ISO_OK=0
    fi
done

# Detection content, independent of any signature: the hash of the evidence vector.
if [ -f "$A/computed_detection_evidence_log.csv" ]; then
    ha=$(cut -d',' -f22 "$A/computed_detection_evidence_log.csv" | md5sum | cut -d' ' -f1)
    hb=$(cut -d',' -f22 "$B/computed_detection_evidence_log.csv" | md5sum | cut -d' ' -f1)
    [ "$ha" = "$hb" ] && printf '  %-42s IDENTICAL\n' "evidenceVectorHashHex (all rows)" \
                      || { printf '  %-42s ***DIFFERS***\n' "evidenceVectorHashHex (all rows)"; ISO_OK=0; }
fi
echo
[ $ISO_OK -eq 1 ] && echo "  isolation contract: HELD" \
                  || echo "  isolation contract: VIOLATED — investigate before trusting arm B"

echo
echo "=========================================================="
echo " SCORING — this is what is SUPPOSED to differ"
echo "=========================================================="
for arm in "A gate=1 (oracle)" "B gate=0 (oracle-free)"; do
    set -- $arm
    d=$([ "$1" = "A" ] && echo "$A" || echo "$B")
    echo "  --- arm $1 $3 ---"
    if [ -f "$d/metrics_M5_M6_detection_quality.csv" ]; then
        head -1 "$d/metrics_M5_M6_detection_quality.csv"
        tail -1 "$d/metrics_M5_M6_detection_quality.csv"
    fi
done

echo
echo "=========================================================="
echo " PER-SIGNATURE ATTRIBUTION (unit = identity, not packet)"
echo "=========================================================="
for arm in "A gate=1 (oracle)" "B gate=0 (oracle-free)"; do
    set -- $arm
    d=$([ "$1" = "A" ] && echo "$A" || echo "$B")
    echo "  --- arm $1 $3 ---"
    if [ -f "$d/lwssd_flag_attribution.csv" ]; then
        column -t -s, "$d/lwssd_flag_attribution.csv" | sed 's/^/    /'
    else
        echo "    (absent)"
    fi
done

echo
echo "Dataset: $DS_REL"
