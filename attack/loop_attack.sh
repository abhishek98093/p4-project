#!/usr/bin/env bash
# loop_attack.sh — Continuous rotating attack cycle
# ===================================================
#
# Splits the total duration into equal slices and cycles through all 10
# attack scenarios (A through J) back-to-back in a loop. When it reaches
# J it wraps back to A and keeps going until total time expires.
#
# This creates a MIXED attack dataset where the classifier sees rapid
# transitions between attack types — much harder to detect than a single
# sustained flood, and realistic because real botnets rotate techniques.
#
# ═══════════════════════════════════════════════════════════════════════
# USAGE (from Mininet CLI, one line)
# ═══════════════════════════════════════════════════════════════════════
#
#   mininet> sh bash /opt/p4work/arp_flood_detection/attack/loop_attack.sh <TOTAL_DURATION> <PPS>
#
#   Arg 1 = TOTAL_DURATION  total seconds to run  (default: 600 = 10 min)
#   Arg 2 = PPS             packets/sec per attacker (default: 1500)
#
# Examples:
#   # 10 minutes, rotating all attacks, 1500 pps:
#   mininet> sh bash /opt/p4work/arp_flood_detection/attack/loop_attack.sh 600 1500
#
#   # 5 minutes, 1000 pps:
#   mininet> sh bash /opt/p4work/arp_flood_detection/attack/loop_attack.sh 300 1000
#
#   # 20 minutes, 2000 pps:
#   mininet> sh bash /opt/p4work/arp_flood_detection/attack/loop_attack.sh 1200 2000
#
# ═══════════════════════════════════════════════════════════════════════
# HOW IT WORKS
# ═══════════════════════════════════════════════════════════════════════
#
# 10 scenarios: A B C D E F G H I J
# Each gets (TOTAL_DURATION / 10) seconds per cycle.
#
# Example with 600s total:
#   0-60s    → Scenario A (DDoS flood, many->one)
#   60-120s  → Scenario B (MAC-spoof flood)
#   120-180s → Scenario C (IP-spoof flood)
#   180-240s → Scenario D (Combo spoof, many->one)
#   240-300s → Scenario E (Coordinated MITM)
#   300-360s → Scenario F (Chaos, many->many)
#   360-420s → Scenario G (Stealth in crowd)
#   420-480s → Scenario H (Scan then flood)
#   480-540s → Scenario I (Moderate single, ~150pps)
#   540-600s → Scenario J (Moderate distributed, ~200pps)
#
# If TOTAL_DURATION > one full cycle, it wraps: after J, starts A again.
# Example with 1200s: A B C D E F G H I J A B C D E F G H I J
#
# Between each scenario there's a 3-second cleanup gap where all
# attack processes are killed, so the controller sees a brief lull
# between attack types — this helps label boundaries in the CSV.
#
# ═══════════════════════════════════════════════════════════════════════

set -u

TOTAL_DURATION="${1:-600}"
PPS="${2:-1500}"

ATTACK_SH="/opt/p4work/arp_flood_detection/attack/run_attack.sh"
LOGDIR="/tmp"

if [[ ! -f "$ATTACK_SH" ]]; then
    echo "ERROR: $ATTACK_SH not found" >&2
    exit 1
fi

# All 10 scenarios in order
SCENARIOS=(A B C D E F G H I J)
NUM_SCENARIOS=${#SCENARIOS[@]}

# Each scenario gets an equal time slice
SLICE=$((TOTAL_DURATION / NUM_SCENARIOS))
if [[ "$SLICE" -lt 5 ]]; then
    echo "ERROR: Total duration too short. Need at least $((NUM_SCENARIOS * 5))s (${NUM_SCENARIOS} scenarios x 5s minimum each)" >&2
    exit 1
fi

# Cleanup gap between scenarios (seconds)
GAP=3

SCENARIO_NAMES=(
    "A: DDoS flood (many->one)"
    "B: MAC-spoof flood (one->many)"
    "C: IP-spoof flood (one->one)"
    "D: Combo spoof (many->one)"
    "E: Coordinated MITM poisoning"
    "F: Chaos (many->many, mixed modes)"
    "G: Stealth in crowd (attackers+normals)"
    "H: Scan then flood (two-phase)"
    "I: Moderate single (~150pps, 10k cap)"
    "J: Moderate distributed (~200pps, 10k cap)"
)

echo "============================================================"
echo " Loop Attack — Rotating Scenario Cycle"
echo "   Total duration : ${TOTAL_DURATION}s"
echo "   Per scenario   : ${SLICE}s"
echo "   PPS            : ${PPS}"
echo "   Scenarios      : ${SCENARIOS[*]}"
echo "   Cleanup gap    : ${GAP}s between each"
echo "============================================================"
echo ""

T_START=$(date +%s)
T_END=$((T_START + TOTAL_DURATION))
ROUND=1
TOTAL_SENT=0

while true; do
    NOW=$(date +%s)
    REMAINING=$((T_END - NOW))
    if [[ "$REMAINING" -le 0 ]]; then
        break
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " ROUND ${ROUND}  |  Elapsed: $((NOW - T_START))s  |  Remaining: ${REMAINING}s"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for i in "${!SCENARIOS[@]}"; do
        NOW=$(date +%s)
        REMAINING=$((T_END - NOW))
        if [[ "$REMAINING" -le 0 ]]; then
            break 2
        fi

        SCEN="${SCENARIOS[$i]}"
        SCEN_NAME="${SCENARIO_NAMES[$i]}"

        # Use remaining time if it's less than a full slice
        THIS_SLICE=$SLICE
        if [[ "$REMAINING" -lt "$THIS_SLICE" ]]; then
            THIS_SLICE=$REMAINING
        fi

        # Skip if not enough time for a meaningful run
        if [[ "$THIS_SLICE" -lt 3 ]]; then
            break 2
        fi

        ELAPSED=$((NOW - T_START))
        echo ""
        echo "[+${ELAPSED}s] ▶ ${SCEN_NAME}  (${THIS_SLICE}s)"
        echo "         log: ${LOGDIR}/atk_*.log"

        # Launch the scenario
        bash "$ATTACK_SH" "$SCEN" "$THIS_SLICE" "$PPS" 2>&1 | \
            sed 's/^/         /'

        # Wait for the scenario to finish
        sleep "$THIS_SLICE"

        # Kill any stragglers from this scenario
        pkill -f "attack_traffic.py" 2>/dev/null || true
        # Also kill normal_traffic.py if scenario G was running
        if [[ "$SCEN" == "G" || "$SCEN" == "g" ]]; then
            pkill -f "normal_traffic.py" 2>/dev/null || true
        fi

        TOTAL_SENT=$((TOTAL_SENT + 1))

        # Brief gap so the controller sees a lull between attack types
        NOW=$(date +%s)
        if [[ $((T_END - NOW)) -gt "$GAP" ]]; then
            echo "         [gap ${GAP}s — cleanup]"
            sleep "$GAP"
        fi
    done

    ROUND=$((ROUND + 1))
done

ACTUAL_ELAPSED=$(( $(date +%s) - T_START ))
echo ""
echo "============================================================"
echo " Loop Attack DONE"
echo "   Ran ${TOTAL_SENT} scenario slices in ${ACTUAL_ELAPSED}s"
echo "   Completed $((ROUND - 1)) full/partial rounds"
echo "============================================================"

# Final cleanup
pkill -f "attack_traffic.py" 2>/dev/null || true
pkill -f "normal_traffic.py" 2>/dev/null || true
