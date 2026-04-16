# run_scenario.py  —  One-shot demo scenario runner
#
# Launch everything with ONE command inside Mininet CLI:
#
#   mininet> py exec(open('/opt/p4work/arp_flood_detection/attack/run_scenario.py').read())
#
# This starts normal background traffic on h2, h4, h9, h14 and an ARP
# attack suite on h1 — all in one shot, all backgrounded.
#
# To stop early:
#   mininet> sh pkill -f "arp_attack_suite|normal_traffic"
#
# Watch logs:
#   mininet> sh tail -f /tmp/h1_attack.log
#   mininet> sh tail -f /tmp/h2_normal.log

BASE = "/opt/p4work/arp_flood_detection/attack"

# ── Config ──────────────────────────────────────────────────────────────
NORMAL_HOSTS   = ['h2', 'h4', 'h9', 'h14']   # hosts running normal traffic
NORMAL_SECS    = 600                          # normal traffic duration
ATTACKER       = 'h1'                         # attacker host
ATTACK_DELAY   = 20                           # seconds of baseline before attack
ATTACK_SECS    = 480                          # attack duration (8 min)
ATTACK_PPS     = 1200                         # attack rate
ATTACK_MODE    = 'all'                        # 'all' = cycle 25 attacks

# ── Launch normal traffic (4 hosts, backgrounded) ───────────────────────
print("=" * 60)
print("DEMO SCENARIO LAUNCH")
print("=" * 60)

for h in NORMAL_HOSTS:
    cmd = (f"python3 {BASE}/normal_traffic.py "
           f"--iface {h}-eth0 --duration {NORMAL_SECS} "
           f"> /tmp/{h}_normal.log 2>&1 &")
    net.get(h).cmd(cmd)
    print(f"  [+] {h}: normal traffic for {NORMAL_SECS}s  ->  /tmp/{h}_normal.log")

# ── Launch attacker (delayed start, backgrounded) ───────────────────────
attack_cmd = (
    f"sleep {ATTACK_DELAY} && "
    f"python3 {BASE}/arp_attack_suite.py "
    f"--iface {ATTACKER}-eth0 --attack {ATTACK_MODE} "
    f"--duration {ATTACK_SECS} --pps {ATTACK_PPS} "
    f"> /tmp/{ATTACKER}_attack.log 2>&1 &"
)
net.get(ATTACKER).cmd(attack_cmd)
print(f"  [+] {ATTACKER}: attack '{ATTACK_MODE}' in {ATTACK_DELAY}s "
      f"({ATTACK_SECS}s @ {ATTACK_PPS}pps)  ->  /tmp/{ATTACKER}_attack.log")

# ── Instructions ────────────────────────────────────────────────────────
print("=" * 60)
print("TIMELINE:")
print(f"  t=0s    : normal baseline begins on {','.join(NORMAL_HOSTS)}")
print(f"  t={ATTACK_DELAY}s   : {ATTACKER} starts cycling 25 attacks")
print(f"  t={ATTACK_DELAY+ATTACK_SECS}s  : attack ends, baseline continues")
print(f"  t={NORMAL_SECS}s  : normal traffic ends (scenario complete)")
print()
print("WATCH PROGRESS:")
print(f"  mininet> sh tail -f /tmp/{ATTACKER}_attack.log")
print()
print("STOP EARLY:")
print("  mininet> sh pkill -f 'arp_attack_suite|normal_traffic'")
print("=" * 60)
