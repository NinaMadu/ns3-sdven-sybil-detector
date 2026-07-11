#!/bin/bash
# Show current simulated time / attack-type phase of every seq6 pct-sweep run.
# Usage:
#   bash sybil-attack/commands/monitor_progress.sh          # one snapshot
#   bash sybil-attack/commands/monitor_progress.sh -w       # live, refresh every 15s
#   bash sybil-attack/commands/monitor_progress.sh -w 5     # live, refresh every 5s
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

snapshot() {
    local found=0 f d t per clk
    for f in "$SIM_DIR"/sybil-attack/datasets/seq6_pct_sweep_*/*/run_meta.json; do
        [ -f "$f" ] || continue; found=1
        d=$(dirname "$f")
        # True sim clock = last receive_time in communication_log.csv (col 1).
        # Fall back to the evidence log, which can stop advancing in late phases
        # even while the sim keeps running.
        clk="$d/communication_log.csv"
        [ -s "$clk" ] || clk="$d/computed_detection_evidence_log.csv"
        t=$(tail -1 "$clk" 2>/dev/null | cut -d, -f1)
        case "$t" in ''|*[!0-9.]*) t=0 ;; esac
        per=$(grep -oE '"sim_time_per_phase": *[0-9]+' "$d/run_meta.json" 2>/dev/null | grep -oE '[0-9]+')
        per=${per:-48}
        awk -v t="${t:-0}" -v per="$per" -v id="$(basename "$d")" \
            'BEGIN{tot=per*6;ph=int(t/per)+1;if(ph>6)ph=6;
                   printf "  %-14s t=%.1f/%ds (%d%%)  attack type %d/6\n",id,t,tot,int(t/tot*100),ph}'
    done
    [ "$found" = 0 ] && echo "  (no evidence CSVs yet — run not started or still in setup)"
    if pgrep -af 'Sybil-Developing-Improved' >/dev/null 2>&1; then
        echo "  live: $(pgrep -af 'Sybil-Developing-Improved' | grep -oE 'runId=[^ ]+' | paste -sd' ' -)"
    else
        echo "  live: no sim process running"
    fi
}

if [ "${1:-}" = "-w" ]; then
    while true; do clear; date; snapshot; sleep "${2:-15}"; done
else
    snapshot
fi
