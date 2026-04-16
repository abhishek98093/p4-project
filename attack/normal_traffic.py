#!/usr/bin/env python3
"""
normal_traffic.py  —  Realistic background traffic generator

Simulates a normal host doing everyday networking:
  - Occasional pings to other hosts (ICMP)
  - Occasional ARP requests (legitimate, real src MAC/IP)
  - Occasional short TCP connects (nc)
  - Random idle gaps between actions

Run on one or more hosts in parallel to create a realistic baseline
for contrast against arp_flood.py attack runs.

Usage (from Mininet CLI):
    mininet> h1 python3 /opt/p4work/arp_flood_detection/attack/normal_traffic.py \
                 --iface h1-eth0 --duration 60

    # Run on several hosts at once:
    mininet> h1 python3 .../normal_traffic.py --iface h1-eth0 --duration 120 &
    mininet> h3 python3 .../normal_traffic.py --iface h3-eth0 --duration 120 &
    mininet> h9 python3 .../normal_traffic.py --iface h9-eth0 --duration 120 &
"""

import argparse
import random
import subprocess
import sys
import time

try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy not installed. Run: sudo apt install python3-scapy\n")
    sys.exit(1)


# All 16 host IPs in the testbed (10.1.1.1..10.1.8.1 and 10.2.1.1..10.2.8.1)
ALL_HOSTS = [f"10.{sw}.{j}.1" for sw in (1, 2) for j in range(1, 9)]


def pick_target(my_ip):
    """Pick a random peer IP that isn't us."""
    choices = [ip for ip in ALL_HOSTS if ip != my_ip]
    return random.choice(choices)


def action_ping(target):
    """One ping, short timeout — generates ARP + ICMP naturally."""
    subprocess.run(
        ["ping", "-c", "1", "-W", "1", target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"ping {target}"


def action_ping_burst(target):
    """A small burst of 3-5 pings — typical app checking liveness."""
    n = random.randint(3, 5)
    subprocess.run(
        ["ping", "-c", str(n), "-i", "0.2", "-W", "1", target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"ping x{n} {target}"


def action_arp_request(iface, real_mac, real_ip, target):
    """One legitimate ARP request — real src, asking about a real host."""
    pkt = (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
           ARP(op=1, hwsrc=real_mac, psrc=real_ip,
               hwdst="00:00:00:00:00:00", pdst=target))
    sendp(pkt, iface=iface, verbose=False)
    return f"arp-req {target}"


def action_tcp_connect(target):
    """Short TCP connect attempt — triggers ARP + SYN."""
    port = random.choice([22, 80, 443, 8080])
    subprocess.run(
        ["nc", "-zw1", target, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"tcp {target}:{port}"


def main():
    ap = argparse.ArgumentParser(description="Normal background traffic generator")
    ap.add_argument("--iface", required=True, help="Interface (e.g. h1-eth0)")
    ap.add_argument("--duration", type=int, default=60,
                    help="How long to run in seconds (default: 60)")
    ap.add_argument("--min-gap", type=float, default=0.5,
                    help="Min seconds between actions (default: 0.5)")
    ap.add_argument("--max-gap", type=float, default=3.0,
                    help="Max seconds between actions (default: 3.0)")
    ap.add_argument("--verbose", action="store_true", help="Log every action")
    args = ap.parse_args()

    try:
        real_mac = get_if_hwaddr(args.iface)
        real_ip = get_if_addr(args.iface)
    except Exception as e:
        sys.stderr.write(f"Failed to read iface {args.iface}: {e}\n")
        sys.exit(1)

    print(f"[normal] iface={args.iface}  src={real_ip} ({real_mac})")
    print(f"[normal] duration={args.duration}s  gap={args.min_gap}-{args.max_gap}s")

    # Weighted action mix — what a real host does most of the time.
    # Pings and TCP connects dominate; explicit ARPs are rarer because
    # most ARPs happen implicitly inside ping/nc anyway.
    actions = [
        ("ping",        35),
        ("ping_burst",  20),
        ("tcp",         30),
        ("arp_req",     15),
    ]
    pool = []
    for name, weight in actions:
        pool.extend([name] * weight)

    t_start = time.time()
    t_end = t_start + args.duration
    n_actions = 0

    while time.time() < t_end:
        target = pick_target(real_ip)
        choice = random.choice(pool)

        try:
            if choice == "ping":
                desc = action_ping(target)
            elif choice == "ping_burst":
                desc = action_ping_burst(target)
            elif choice == "tcp":
                desc = action_tcp_connect(target)
            elif choice == "arp_req":
                desc = action_arp_request(args.iface, real_mac, real_ip, target)
        except Exception as e:
            desc = f"error: {e}"

        n_actions += 1
        if args.verbose:
            elapsed = time.time() - t_start
            print(f"[normal] +{elapsed:5.1f}s  {desc}")

        # Random idle gap — this is what makes it look "normal"
        time.sleep(random.uniform(args.min_gap, args.max_gap))

    elapsed = time.time() - t_start
    print(f"[normal] done. {n_actions} actions in {elapsed:.1f}s "
          f"(~{n_actions/elapsed:.1f} actions/sec)")


if __name__ == "__main__":
    main()
