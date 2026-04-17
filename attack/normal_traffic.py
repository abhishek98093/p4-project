#!/usr/bin/env python3
"""
normal_traffic.py — Realistic Background Traffic Generator
==========================================================

Simulates the kind of traffic a real host on a LAN produces:
  • One-to-many   — busy client talking to several servers/peers
  • Many-to-one   — clients fanning in to a "server" host
  • Many-to-many  — random office-chatter between peers
  • Request/reply conversations (ARP->reply, ICMP->echo-reply, TCP SYN->SYN-ACK)
  • Gratuitous ARP only occasionally (every ~30-120s) as Linux actually does.
  • Poisson-distributed inter-packet gaps + idle "think time" periods.

THREE INTENSITY MODES
---------------------
  quiet   — Low activity. Long idle gaps, few actions. Think "night shift, one
            person checking email every few minutes." Produces very light ARP
            background (~2-5 ARPs per 3s controller window).

  normal  — Typical office hour. Moderate mix of TCP, ICMP, ARP. This is the
            default and covers the majority of real-world baseline traffic.
            (~10-30 ARPs per 3s window from implicit + explicit combined.)

  busy    — Peak hour / large office. Many concurrent flows, shorter gaps,
            more multi-ping sweeps, higher TCP rate. Think "Monday 9 AM,
            everyone logging in at once." (~30-80 ARPs per 3s window, still
            legitimate because it's all real-MAC, real-IP, cached.)

All three modes use REAL MACs, REAL IPs, and respect ARP caching — so even
"busy" mode looks nothing like an attack in feature space. The classifier must
learn that high rate alone doesn't mean attack; it's the MAC/IP spoofing,
broadcast ratio, and consistency violations that distinguish floods.

USAGE (from Mininet CLI)
------------------------
  # Default (normal intensity):
  mininet> h1 python3 .../normal_traffic.py --iface h1-eth0 --role client --duration 120

  # Quiet (night shift):
  mininet> h1 python3 .../normal_traffic.py --iface h1-eth0 --role client \
               --intensity quiet --duration 120

  # Busy (peak hour):
  mininet> h1 python3 .../normal_traffic.py --iface h1-eth0 --role client \
               --intensity busy --duration 120

ROLES
-----
  client  — Initiates traffic only (workstation)
  server  — Accepts TCP connections only (web/SSH server)
  peer    — Both (developer machine with local services)

DEPENDENCIES
------------
    sudo apt install python3-scapy iputils-ping netcat-openbsd
"""

import argparse
import os
import random
import socket
import subprocess
import sys
import threading
import time

try:
    from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_addr
except ImportError:
    sys.stderr.write("scapy not installed. Run: sudo apt install python3-scapy\n")
    sys.exit(1)


# ── Topology knowledge ────────────────────────────────────────────────────────
# 16 hosts: 10.1.1.1..10.1.8.1  and  10.2.1.1..10.2.8.1
ALL_HOSTS = [f"10.{sw}.{j}.1" for sw in (1, 2) for j in range(1, 9)]

# Ports for fake "services"
SERVER_PORTS = [22, 80, 443, 8080, 5000]


# ── Intensity profiles ────────────────────────────────────────────────────────
# Each profile defines timing and behavior parameters that shape how much
# traffic the host generates. All three still use REAL MAC/IP and respect
# ARP caching — only the RATE and MIX change, not the legitimacy.

INTENSITY_PROFILES = {
    "quiet": {
        "mean_gap":         3.5,    # avg seconds between actions (slow)
        "grat_arp_min":     60,     # gratuitous ARP every 60-180s
        "grat_arp_max":     180,
        "idle_period_min":  20,     # idle periods start after 20-60s
        "idle_period_max":  60,
        "idle_duration_min": 8,     # idle lasts 8-25s (long pauses)
        "idle_duration_max": 25,
        "next_idle_min":    20,     # gap between idle periods
        "next_idle_max":    60,
        "max_gap_clamp":    8.0,    # max single inter-action gap
        "actions": [                # weighted action pool
            ("tcp_connect",  25),   # short probes — less data
            ("ping",         30),   # single pings dominate
            ("ping_burst",    5),   # rare burst
            ("multi_ping",    2),   # very rare sweep
            ("arp_req",       8),   # uncommon
            ("tcp_exchange", 15),   # some real requests
            ("idle",         15),   # lots of "do nothing"
        ],
        "description": "Low activity (night shift / single user)",
    },
    "normal": {
        "mean_gap":         1.2,    # moderate pace
        "grat_arp_min":     30,
        "grat_arp_max":     120,
        "idle_period_min":  15,
        "idle_period_max":  40,
        "idle_duration_min": 5,
        "idle_duration_max": 15,
        "next_idle_min":    30,
        "next_idle_max":    90,
        "max_gap_clamp":    6.0,
        "actions": [
            ("tcp_exchange", 35),   # heaviest — real request/response
            ("tcp_connect",  20),   # short probes
            ("ping",         15),   # single ping
            ("ping_burst",   10),   # liveness check
            ("multi_ping",    8),   # 1-to-many sweep
            ("arp_req",       7),   # explicit ARP
            ("idle",          5),   # "user thinking"
        ],
        "description": "Typical office-hour traffic",
    },
    "busy": {
        "mean_gap":         0.4,    # fast pace — lots of concurrent activity
        "grat_arp_min":     20,
        "grat_arp_max":     60,
        "idle_period_min":  30,
        "idle_period_max":  80,
        "idle_duration_min": 2,     # short pauses — busy person
        "idle_duration_max": 5,
        "next_idle_min":    60,
        "next_idle_max":    180,
        "max_gap_clamp":    3.0,
        "actions": [
            ("tcp_exchange", 40),   # lots of web/API calls
            ("tcp_connect",  22),   # frequent probes
            ("ping",         10),
            ("ping_burst",   10),
            ("multi_ping",   10),   # monitoring tools, health checks
            ("arp_req",       5),
            ("idle",          3),   # rarely sits still
        ],
        "description": "Peak hour (Monday 9 AM / large office)",
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def pick_target(my_ip, exclude=None):
    """Pick a random peer IP that isn't us."""
    exclude = exclude or set()
    choices = [ip for ip in ALL_HOSTS if ip != my_ip and ip not in exclude]
    return random.choice(choices) if choices else None


def pick_targets(my_ip, k):
    """Pick k distinct peer IPs."""
    choices = [ip for ip in ALL_HOSTS if ip != my_ip]
    k = min(k, len(choices))
    return random.sample(choices, k)


def poisson_gap(mean_sec):
    """Exponential (Poisson inter-arrival) gap — more natural than uniform."""
    return random.expovariate(1.0 / max(mean_sec, 0.01))


# ── Traffic actions (client side) ─────────────────────────────────────────────
def action_ping_once(target):
    """Single ping — one ARP (if uncached) + one ICMP echo + reply."""
    subprocess.run(
        ["ping", "-c", "1", "-W", "1", target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"ping {target}"


def action_ping_burst(target):
    """Small burst of pings — typical app liveness probe."""
    n = random.randint(3, 6)
    subprocess.run(
        ["ping", "-c", str(n), "-i", "0.2", "-W", "1", target],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"ping x{n} {target}"


def action_tcp_connect(target, port=None):
    """Short TCP connect — causes ARP (if uncached) + SYN + SYN-ACK + RST/FIN."""
    port = port or random.choice(SERVER_PORTS)
    subprocess.run(
        ["nc", "-zw1", target, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return f"tcp-connect {target}:{port}"


def action_tcp_exchange(target, port=None):
    """TCP connect + small payload exchange. Real request/response."""
    port = port or random.choice(SERVER_PORTS)
    try:
        with socket.create_connection((target, port), timeout=1.5) as s:
            s.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            try:
                s.settimeout(0.8)
                s.recv(512)
            except (socket.timeout, OSError):
                pass
    except (socket.timeout, OSError):
        pass
    return f"tcp-exchange {target}:{port}"


def action_multi_ping(my_ip):
    """One-to-many: ping 3-5 different hosts back-to-back."""
    targets = pick_targets(my_ip, random.randint(3, 5))
    for t in targets:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", t],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(random.uniform(0.05, 0.2))
    return f"multi-ping x{len(targets)}"


def action_arp_request(iface, real_mac, real_ip, target):
    """Explicit ARP request — real src MAC/IP, looking up a real host."""
    pkt = (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
           ARP(op=1, hwsrc=real_mac, psrc=real_ip,
               hwdst="00:00:00:00:00:00", pdst=target))
    sendp(pkt, iface=iface, verbose=False)
    return f"arp-req {target}"


def action_gratuitous_arp(iface, real_mac, real_ip):
    """Gratuitous ARP — announces own IP. Rare but normal."""
    pkt = (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
           ARP(op=1, hwsrc=real_mac, psrc=real_ip,
               hwdst="ff:ff:ff:ff:ff:ff", pdst=real_ip))
    sendp(pkt, iface=iface, verbose=False)
    return "grat-arp"


# ── Server role ───────────────────────────────────────────────────────────────
def server_accept_loop(port, stop_evt):
    """Tiny TCP echo/HTTP-ish server. Accepts, replies, closes."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(8)
        s.settimeout(0.5)
    except OSError as e:
        print(f"[server] port {port} bind failed: {e}")
        return

    while not stop_evt.is_set():
        try:
            conn, _addr = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.settimeout(0.5)
            try:
                conn.recv(512)
            except (socket.timeout, OSError):
                pass
            try:
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        s.close()
    except OSError:
        pass


def start_servers(ports):
    """Start one accept thread per port."""
    stop_evt = threading.Event()
    threads = []
    for p in ports:
        t = threading.Thread(target=server_accept_loop, args=(p, stop_evt),
                             daemon=True, name=f"srv-{p}")
        t.start()
        threads.append(t)
    return threads, stop_evt


# ── Client behavior ───────────────────────────────────────────────────────────
def build_action_pool(profile):
    """Build weighted action pool from profile."""
    pool = []
    for name, weight in profile["actions"]:
        pool.extend([name] * weight)
    return pool


def run_client_loop(iface, real_mac, real_ip, duration, profile, verbose):
    """
    Main client loop. Sends bursts, idles, sends more.
    All timing and mix parameters come from the intensity profile.
    """
    pool = build_action_pool(profile)
    mean_gap = profile["mean_gap"]
    max_gap  = profile["max_gap_clamp"]

    t_start = time.time()
    t_end   = t_start + duration
    n_actions = 0

    # Schedule first gratuitous ARP
    next_grat = time.time() + random.uniform(
        profile["grat_arp_min"], profile["grat_arp_max"])

    # Schedule first idle period
    next_idle_period = time.time() + random.uniform(
        profile["idle_period_min"], profile["idle_period_max"])

    while time.time() < t_end:
        now = time.time()

        # Occasional gratuitous ARP (rare, scheduled)
        if now >= next_grat:
            try:
                desc = action_gratuitous_arp(iface, real_mac, real_ip)
                if verbose:
                    print(f"[normal] +{now - t_start:5.1f}s  {desc}")
            except Exception as e:
                if verbose:
                    print(f"[normal] grat-arp err: {e}")
            next_grat = now + random.uniform(
                profile["grat_arp_min"], profile["grat_arp_max"])

        # Occasional long idle period — user away from desk
        if now >= next_idle_period:
            idle_for = random.uniform(
                profile["idle_duration_min"], profile["idle_duration_max"])
            if verbose:
                print(f"[normal] +{now - t_start:5.1f}s  (idle {idle_for:.1f}s)")
            time.sleep(min(idle_for, max(0, t_end - time.time())))
            next_idle_period = time.time() + random.uniform(
                profile["next_idle_min"], profile["next_idle_max"])
            continue

        # Pick an action
        choice = random.choice(pool)
        target = pick_target(real_ip)
        if target is None:
            break

        try:
            if choice == "tcp_exchange":
                desc = action_tcp_exchange(target)
            elif choice == "tcp_connect":
                desc = action_tcp_connect(target)
            elif choice == "ping":
                desc = action_ping_once(target)
            elif choice == "ping_burst":
                desc = action_ping_burst(target)
            elif choice == "multi_ping":
                desc = action_multi_ping(real_ip)
            elif choice == "arp_req":
                desc = action_arp_request(iface, real_mac, real_ip, target)
            elif choice == "idle":
                desc = "idle"
                time.sleep(random.uniform(1.0, 3.0))
            else:
                desc = f"unknown:{choice}"
        except Exception as e:
            desc = f"error: {e}"

        n_actions += 1
        if verbose:
            elapsed = time.time() - t_start
            print(f"[normal] +{elapsed:5.1f}s  {desc}")

        # Poisson-distributed gap between actions
        gap = poisson_gap(mean_gap)
        gap = max(0.05, min(gap, max_gap))  # clamp extremes
        time.sleep(gap)

    return n_actions


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Realistic normal traffic generator")
    ap.add_argument("--iface", required=True,
                    help="Interface (e.g. h1-eth0)")
    ap.add_argument("--role", choices=["client", "server", "peer"],
                    default="client",
                    help="client=talks out, server=accepts only, peer=both")
    ap.add_argument("--intensity", choices=["quiet", "normal", "busy"],
                    default="normal",
                    help="Traffic intensity: quiet (night shift), "
                         "normal (office hour), busy (peak hour)")
    ap.add_argument("--duration", type=int, default=120,
                    help="How long to run in seconds (default: 120)")
    ap.add_argument("--verbose", action="store_true",
                    help="Log every action to stdout")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write("Needs root (scapy + raw sockets).\n")
        sys.exit(1)

    try:
        real_mac = get_if_hwaddr(args.iface)
        real_ip  = get_if_addr(args.iface)
    except Exception as e:
        sys.stderr.write(f"Failed to read iface {args.iface}: {e}\n")
        sys.exit(1)

    profile = INTENSITY_PROFILES[args.intensity]

    print(f"[normal] iface={args.iface}  src={real_ip} ({real_mac})")
    print(f"[normal] role={args.role}  intensity={args.intensity}  "
          f"duration={args.duration}s")
    print(f"[normal] profile: {profile['description']}  "
          f"mean_gap={profile['mean_gap']}s")

    server_threads, server_stop = [], None

    # Start server threads if role includes accepting
    if args.role in ("server", "peer"):
        server_threads, server_stop = start_servers(SERVER_PORTS)
        print(f"[normal] serving on ports {SERVER_PORTS}")

    t_start = time.time()
    n_actions = 0
    try:
        if args.role in ("client", "peer"):
            n_actions = run_client_loop(
                args.iface, real_mac, real_ip,
                args.duration, profile, args.verbose,
            )
        else:
            # Pure server: just sit and accept until duration expires.
            end = t_start + args.duration
            while time.time() < end:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("[normal] interrupted.")
    finally:
        if server_stop is not None:
            server_stop.set()
            for t in server_threads:
                t.join(timeout=1.0)

    elapsed = time.time() - t_start
    if args.role == "server":
        print(f"[normal] server done. ran {elapsed:.1f}s")
    else:
        rate = n_actions / elapsed if elapsed > 0 else 0
        print(f"[normal] done. {n_actions} actions in {elapsed:.1f}s "
              f"(~{rate:.2f} actions/sec)")


if __name__ == "__main__":
    main()