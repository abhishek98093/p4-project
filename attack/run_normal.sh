#!/usr/bin/env bash
# run_normal.sh — Launch realistic normal traffic on all 16 Mininet hosts.
#
# How it works:
#   Each Mininet host is a separate network namespace. When Mininet boots, it
#   drops a PID file per host at /tmp/mn.<host>.pid (or similar). We enter
#   each host's namespace using `mnexec -a <pid>` and run normal_traffic.py
#   there — so every instance uses the right interface (hN-eth0) with the
#   correct IP and MAC, exactly as if typed in the Mininet CLI.
#
# Usage (from Mininet CLI, one line):
#     mininet> sh bash /opt/p4work/arp_flood_detection/attack/run_normal.sh 180
#
# Or from the host shell (also one line):
#     sudo bash /opt/p4work/arp_flood_detection/attack/run_normal.sh 180
#
# Arg 1 = duration in seconds (default 180).

set -u

DURATION="${1:-180}"
SCRIPT="/opt/p4work/arp_flood_detection/attack/normal_traffic.py"
LOGDIR="/tmp"

if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: $SCRIPT not found" >&2
    exit 1
fi

# Role assignment — three servers, four peers, nine clients.
declare -A ROLE=(
    [h1]=client   [h2]=client   [h3]=peer     [h4]=server
    [h5]=client   [h6]=peer     [h7]=client   [h8]=server
    [h9]=client   [h10]=peer    [h11]=client  [h12]=server
    [h13]=client  [h14]=peer    [h15]=client  [h16]=client
)

# Find the PID of a Mininet host. Mininet writes these to /tmp/<host>.pid
# but older builds used /tmp/mn.<host>.pid. Try both.
get_host_pid() {
    local h="$1"
    for f in "/tmp/${h}.pid" "/tmp/mn.${h}.pid"; do
        if [[ -f "$f" ]]; then
            cat "$f"
            return 0
        fi
    done
    # Fallback: pick the bash process whose cmdline mentions the host.
    pgrep -f "mininet:${h}$" | head -n 1
}

echo "[run_normal] duration=${DURATION}s  script=${SCRIPT}"

started=0
for h in h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15 h16; do
    role="${ROLE[$h]}"
    iface="${h}-eth0"
    pid="$(get_host_pid "$h")"

    if [[ -z "$pid" ]]; then
        echo "  [$h] SKIP — couldn't find namespace PID (is Mininet running?)"
        continue
    fi

    log="${LOGDIR}/nt_${h}.log"
    echo "  [$h] role=${role} iface=${iface} pid=${pid}  -> ${log}"

    # mnexec -a <pid> enters the host's net namespace exactly like the
    # Mininet CLI does when you type "h1 <cmd>".
    mnexec -a "$pid" \
        python3 "$SCRIPT" \
            --iface "$iface" \
            --role "$role" \
            --duration "$DURATION" \
        >"$log" 2>&1 &

    started=$((started + 1))
done

echo "[run_normal] launched ${started} hosts. Tail logs with:"
echo "    tail -f ${LOGDIR}/nt_h*.log"
echo "[run_normal] will finish in ~${DURATION}s."
