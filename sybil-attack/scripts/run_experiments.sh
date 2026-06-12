#!/bin/bash
# =============================================================================
# run_experiments.sh
# Runs Sybil-Developing-Improved for every (attack_type × attack_percentage)
# combination and saves the terminal output for later parsing.
#
# Usage (from the ns3-sdven-sybil-detector project root):
#   bash sybil-attack/scripts/run_experiments.sh
# =============================================================================

set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────────────
NS3_DIR="${HOME}/FYP/ns-allinone-3.35/ns-3.35"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS_DIR="${PROJECT_DIR}/sybil-attack/results"

mkdir -p "${RESULTS_DIR}"
mkdir -p "${NS3_DIR}/sybil-attack/outputs"   # needed by the simulation

echo "Project : ${PROJECT_DIR}"
echo "ns-3.35 : ${NS3_DIR}"
echo "Results : ${RESULTS_DIR}"
echo ""

# ── Experiment grid ──────────────────────────────────────────────────────────
ATTACK_TYPES=(1 2 3 4)          # 1=Outsider 2=InsiderDirect-Sim 3=InsiderDirect-NonSim 4=InsiderIndirect
ATTACK_PERCENTAGES=(0 10 25 50 75)

TOTAL=$(( ${#ATTACK_TYPES[@]} * ${#ATTACK_PERCENTAGES[@]} ))
RUN=0

cd "${NS3_DIR}"

for atype in "${ATTACK_TYPES[@]}"; do
    for apct in "${ATTACK_PERCENTAGES[@]}"; do
        RUN=$(( RUN + 1 ))
        OUTFILE="${RESULTS_DIR}/result_type${atype}_pct${apct}.txt"

        echo "━━━ [${RUN}/${TOTAL}] attack_type=${atype}  percentage=${apct}%"

        if [ "${apct}" -eq 0 ]; then
            # Baseline: no attack (all types share the same no-attack baseline)
            CMD="Sybil-Developing-Improved --sybil_attack_enabled=false \
                 --sybil_attack_type=${atype} --sybil_attack_percentage=0"
        else
            CMD="Sybil-Developing-Improved --sybil_attack_enabled=true \
                 --sybil_attack_type=${atype} --sybil_attack_percentage=${apct}"
        fi

        # Run simulation; capture stdout+stderr together
        ./waf --run "${CMD}" > "${OUTFILE}" 2>&1 || {
            echo "  [WARN] simulation exited with error — output saved anyway"
        }

        # Quick summary printed to terminal
        grep -E "(M[0-9]|MCC|FPR|MDR|Precision|Recall|TP=)" "${OUTFILE}" \
             | grep -v "^#" | head -20 || true

        echo "  → ${OUTFILE}"
        echo ""
    done
done

echo "All ${TOTAL} experiments done."
echo "Now run:  python3 sybil-attack/scripts/plot_metrics.py"
