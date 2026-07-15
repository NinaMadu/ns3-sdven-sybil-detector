#!/usr/bin/env bash
# ============================================================================
# Monitor the vehicle-tier v2 pipeline started by run_vehicle_tier_v2.sh.
# Safe to run after reconnecting SSH — it only reads status/logs.
#
#   commands/monitor_vehicle_tier_v2.sh          # one-shot snapshot
#   commands/monitor_vehicle_tier_v2.sh live     # auto-refresh every 15s (Ctrl-C to exit)
#   commands/monitor_vehicle_tier_v2.sh logs      # live-tail the CURRENT notebook's log
#   commands/monitor_vehicle_tier_v2.sh mem       # live-tail the RAM/GPU sampler
# ============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/run_vehicle_tier_v2.sh"
LOGDIR="/home/sdvn_defense_sybil/35_sybil_attack_project/ns-allinone-3.35/ns-3.35/sybil-attack/commands/logs/vehicle_tier_v2"

case "${1:-once}" in
  live) watch -n 15 "$RUN status" ;;
  logs)
    cur="$( [ -f "$LOGDIR/current" ] && cat "$LOGDIR/current" )"
    case "$cur" in
      *.ipynb) echo "tailing $cur ..."; tail -n 40 -f "$LOGDIR/${cur%.ipynb}.log" ;;
      *) echo "No notebook currently running (stage: ${cur:-none})."; "$RUN" status ;;
    esac ;;
  mem)  echo "tailing RAM/GPU sampler ..."; tail -n 20 -f "$LOGDIR/mem.log" ;;
  *)    "$RUN" status ;;
esac
