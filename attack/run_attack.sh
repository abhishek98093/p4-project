#!/usr/bin/env bash
# run_attack.sh — Multi-host ARP attack orchestrator
# ===================================================
#
# Drives attack_traffic.py (and optionally normal_traffic.py) across many
# Mininet hosts to simulate realistic DISTRIBUTED attack scenarios, not
# just single-host floods.
#
# Scenarios:
#   A  ddos_flood           Many attackers -> one victim. Classic ARP DDoS.
#   B  one_to_many_spoof    One host, MAC-spoofed flood, rotating targets.
#   C  ip_spoof             One host floods with random src IPs.
#   D  combo_spoof_many     Many attackers, each MAC+IP spoofing -> one victim.
#   E  mitm_coordinated     Two hosts running MITM poisoning on pairs.
#   F  chaos                Many->many: every attacker uses a different mode.
#   G  stealth_in_crowd     Few attackers + many normal hosts (realistic).
#   H  scan_then_flood      Recon phase then flood phase (two-stage).
#   I  moderate_flood       Single attacker, ~10k ARPs total, low rate (~150pps).
#   J  moderate_distributed Three attackers, ~10k ARPs each, moderate rate.
#
# Usage (from Mininet CLI, one line):
#     mininet> sh bash /opt/p4work/arp_flood_detection/attack/run_attack.sh A 60
#
# Or from host shell while Mininet is running:
#     sudo bash /opt/p4work/arp_flood_detection/attack/run_attack.sh A 60
#
# Args:
#     $1  scenario letter  A..H  (default A)
#     $2  duration sec            (default 60)
#     $3  pps per attacker        (default 1500)

set -u

SCEN="${1:-A}"
DURATION="${2:-60}"
PPS="${3:-1500}"

ATTACK_DIR="/opt/p4work/arp_flood_detection/attack"
ATTACK_PY="${ATTACK_DIR}/attack_traffic.py"
NORMAL_PY="${ATTACK_DIR}/normal_traffic.py"
LOGDIR="/tmp"

if [[ ! -f "$ATTACK_PY" ]]; then
    echo "ERROR: $ATTACK_PY not found" >&2
    exit 1
fi

# Resolve a Mininet host's PID (writes vary across Mininet builds).
get_host_pid() {
    local h="$1"
    for f in "/tmp/${h}.pid" "/tmp/mn.${h}.pid"; do
        [[ -f "$f" ]] && { cat "$f"; return 0; }
    done
    pgrep -f "mininet:${h}$" | head -n 1
}

# Launch attack_traffic.py in host $h's namespace.
# Args: host mode [extra args...]
# Optional: set PPS_OVERRIDE before calling to use a different pps for this
# one invocation instead of the script-global $PPS.
launch_attack() {
    local h="$1"; shift
    local mode="$1"; shift
    local pid; pid="$(get_host_pid "$h")"
    if [[ -z "$pid" ]]; then
        echo "  [$h] SKIP (no namespace pid)"
        return
    fi
    local pps="${PPS_OVERRIDE:-$PPS}"
    local log="${LOGDIR}/atk_${h}_${mode}.log"
    echo "  [$h] mode=${mode}  pps=${pps}  args=$*  -> ${log}"
    mnexec -a "$pid" \
        python3 "$ATTACK_PY" \
            --iface "${h}-eth0" \
            --mode "$mode" \
            --duration "$DURATION" \
            --pps "$pps" \
            --label "${h}/${mode}" \
            "$@" \
        >"$log" 2>&1 &
    unset PPS_OVERRIDE
}

# Launch normal_traffic.py in host $h's namespace (for mixed scenarios).
launch_normal() {
    local h="$1"; local role="$2"
    local pid; pid="$(get_host_pid "$h")"
    if [[ -z "$pid" ]]; then
        echo "  [$h] SKIP (no namespace pid)"
        return
    fi
    if [[ ! -f "$NORMAL_PY" ]]; then
        echo "  [$h] SKIP normal (no normal_traffic.py)"
        return
    fi
    local log="${LOGDIR}/nt_${h}.log"
    echo "  [$h] NORMAL role=${role}  -> ${log}"
    mnexec -a "$pid" \
        python3 "$NORMAL_PY" \
            --iface "${h}-eth0" \
            --role "$role" \
            --duration "$DURATION" \
        >"$log" 2>&1 &
}

echo "============================================================"
echo " Scenario: $SCEN     Duration: ${DURATION}s     PPS: $PPS"
echo "============================================================"

case "$SCEN" in
# ── A. DDoS flood — many -> one ──────────────────────────────────────
A|a|ddos_flood)
    echo "[A] DDoS flood: h1, h2, h5, h7, h9, h11  ->  VICTIM 10.2.1.1 (h9)"
    VICTIM="10.2.1.1"
    for h in h1 h2 h5 h7 h11 h13; do
        launch_attack "$h" flood_target --target "$VICTIM"
    done
    ;;

# ── B. One-to-many MAC-spoof ─────────────────────────────────────────
B|b|one_to_many_spoof)
    echo "[B] MAC-spoof flood from h1 rotating random targets"
    launch_attack h1 flood_mac
    ;;

# ── C. IP-spoof from one host ────────────────────────────────────────
C|c|ip_spoof)
    echo "[C] IP-spoof flood from h1 -> 10.2.1.1"
    launch_attack h1 flood_ip --target 10.2.1.1
    ;;

# ── D. Combo MAC+IP spoof from many -> one ───────────────────────────
D|d|combo_spoof_many)
    echo "[D] Many attackers, each MAC+IP spoofing, hammering 10.2.4.1 (h12)"
    VICTIM="10.2.4.1"
    for h in h1 h2 h3 h5 h7 h11; do
        launch_attack "$h" flood_both --target "$VICTIM"
    done
    ;;

# ── E. Coordinated MITM poisoning ────────────────────────────────────
E|e|mitm_coordinated)
    echo "[E] Two attackers running coordinated MITM poisoning"
    # h1 poisons h3 <-> h5 pair; h2 poisons h6 <-> h8 pair.
    # Lower pps because poisoning is slow-and-steady.
    launch_attack h1 mitm_pair --target 10.1.3.1 --spoof-ip 10.1.5.1
    launch_attack h2 mitm_pair --target 10.1.6.1 --spoof-ip 10.1.8.1
    # Plus one gateway poisoner for flavor.
    launch_attack h7 poison_gateway --spoof-ip 10.1.1.1
    ;;

# ── F. Chaos: many->many with different attack types ─────────────────
F|f|chaos)
    echo "[F] Chaos: 6 attackers, each a different mode, varied targets"
    launch_attack h1  flood_basic   --target 10.2.1.1
    launch_attack h3  flood_mac     --target 10.2.2.1
    launch_attack h5  flood_ip      --target 10.2.3.1
    launch_attack h7  flood_both    --target 10.2.4.1
    launch_attack h9  poison_gateway --spoof-ip 10.1.1.1
    launch_attack h11 storm
    ;;

# ── G. Stealth in crowd: attackers mixed with normal hosts ───────────
G|g|stealth_in_crowd)
    echo "[G] Realistic mix: 3 attackers hidden among 13 normal hosts"
    # Normals (servers/peers/clients)
    launch_normal h4  server
    launch_normal h8  server
    launch_normal h12 server
    launch_normal h3  peer
    launch_normal h6  peer
    launch_normal h10 peer
    launch_normal h14 peer
    launch_normal h2  client
    launch_normal h5  client
    launch_normal h9  client
    launch_normal h13 client
    launch_normal h15 client
    launch_normal h16 client
    # Attackers hidden in the crowd
    launch_attack h1  flood_both    --target 10.2.1.1
    launch_attack h7  flood_mac     --target 10.2.3.1
    launch_attack h11 poison_gateway --spoof-ip 10.1.1.1
    ;;

# ── H. Recon then flood (two-phase) ──────────────────────────────────
H|h|scan_then_flood)
    echo "[H] Two-phase: h1 scans then floods; h5 joins flood midway"
    launch_attack h1 scan_then_flood
    # h5 joins the party partway through with a straight flood.
    (sleep $((DURATION / 3)) ; \
     launch_attack h5 flood_both --target 10.2.1.1) &
    ;;

# ── I. Moderate flood — stealthy, bounded to ~10k packets ────────────
I|i|moderate_flood)
    # Rationale: real attackers often throttle below obvious detection
    # thresholds. ~150pps for ~60s = ~9,000 packets. Hard cap at 10,000 so
    # this stays bounded regardless of --duration. Combo MAC+IP spoofing
    # keeps the feature-space signature "attacky" even at low rate.
    echo "[I] Moderate single-attacker flood"
    echo "    h1 -> 10.2.1.1  at ~150pps  cap=10000 packets"
    PPS_OVERRIDE=150 launch_attack h1 flood_both \
        --target 10.2.1.1 \
        --total-packets 10000
    ;;

# ── J. Moderate distributed — 3 attackers, each ~10k packets ─────────
J|j|moderate_distributed)
    echo "[J] Moderate distributed flood (3 attackers, each capped at 10000)"
    echo "    h1, h5, h11  ->  10.2.1.1  at ~200pps each"
    PPS_OVERRIDE=200 launch_attack h1  flood_both --target 10.2.1.1 --total-packets 10000
    PPS_OVERRIDE=200 launch_attack h5  flood_mac  --target 10.2.1.1 --total-packets 10000
    PPS_OVERRIDE=200 launch_attack h11 flood_ip   --target 10.2.1.1 --total-packets 10000
    ;;

*)
    echo "Unknown scenario '$SCEN'. Choose A..J:" >&2
    echo "  A ddos_flood         B one_to_many_spoof   C ip_spoof" >&2
    echo "  D combo_spoof_many   E mitm_coordinated    F chaos" >&2
    echo "  G stealth_in_crowd   H scan_then_flood" >&2
    echo "  I moderate_flood     J moderate_distributed" >&2
    exit 1
    ;;
esac

echo "------------------------------------------------------------"
echo "Running for ${DURATION}s. Tail logs:"
echo "    tail -f ${LOGDIR}/atk_*.log"
[[ "$SCEN" == "G" || "$SCEN" == "g" ]] && \
    echo "    tail -f ${LOGDIR}/nt_*.log"
echo "Kill early:  sudo pkill -f attack_traffic.py"
[[ "$SCEN" == "G" || "$SCEN" == "g" ]] && \
    echo "             sudo pkill -f normal_traffic.py"