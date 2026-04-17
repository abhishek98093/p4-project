#!/usr/bin/env python3
"""
controller.py — ARP Flood Detection Controller (FIXED)
======================================================
Receives PacketIn messages from all switches via CPU veth interfaces.

Works regardless of start order:
  - Mininet first, then controller → connects immediately
  - Controller first, then Mininet → waits, then connects
  - Mininet restarts while controller runs → reconnects automatically

FIX NOTES
---------
1. Capture uses a raw AF_PACKET socket bound with ETH_P_ALL (0x0003) so the
   kernel delivers EVERY ethertype — including the custom frames BMv2 emits
   with a CPU header at byte 0. Using Scapy's default L2ListenSocket binds
   to ETH_P_IP and silently drops non-IP frames, which is why packets were
   being missed.
2. We read raw bytes directly with recvfrom() and parse the CPU header from
   offset 0. No Scapy reserialization, no Ether-layer assumptions — byte 0
   of the frame is exactly what P4 deparsed onto the veth.
3. Non-blocking recv with select() so each sniff thread can exit cleanly
   on shutdown or interface loss.

USAGE:
    # NORMAL traffic (label=0 in CSV):
    sudo python3 controller.py \
        --interfaces s1-cpu1 s2-cpu1 s11-cpu1 \
        --label normal

    # ATTACK traffic (label=1 in CSV):
    sudo python3 controller.py \
        --interfaces s1-cpu1 s2-cpu1 s11-cpu1 \
        --label attack

    # Toggle label at runtime:
    kill -USR1 <pid>
"""

import os, sys, time, struct, math, socket, select
import threading, collections, csv, logging, argparse, signal
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/controller.log"),
    ]
)
log = logging.getLogger("ctrl")

# ── Config ────────────────────────────────────────────────────────────────────
WINDOW_SEC      = 3
CPU_REASON      = 0xAA
DATASET_PATH    = "/opt/p4work/arp_flood_detection/dataset/arp_dataset.csv"
IFACE_RETRY_SEC = 2
ETH_P_ALL       = 0x0003   # capture every ethertype
RECV_BUF_SIZE   = 65535
SO_RCVBUF_BYTES = 16 * 1024 * 1024   # 16 MiB kernel receive buffer
SHUTDOWN        = threading.Event()

# ── CPU Header parser ─────────────────────────────────────────────────────────
# Layout (big-endian), 41 bytes total:
#   B   cpu_reason       (1)
#   B   switch_id        (1)
#   H   ingress_port<<7  (2)   → top 9 bits are the port
#   4s  sender_ip        (4)
#   6s  sender_mac       (6)
#   4s  target_ip        (4)
#   H   opcode           (2)
#   I   reg_total        (4)
#   I   reg_req          (4)
#   I   reg_rep          (4)
#   I   reg_grat         (4)
#   I   reg_bcast        (4)
#   B   reg_ctr          (1)
CPU_FMT  = "!BB H 4s 6s 4s H IIIII B"
CPU_SIZE = struct.calcsize(CPU_FMT)   # = 41

class CpuHeader:
    __slots__ = [
        "switch_id", "ingress_port",
        "sender_ip", "sender_mac", "target_ip", "opcode",
        "reg_total", "reg_req", "reg_rep",
        "reg_grat",  "reg_bcast", "reg_ctr",
    ]

    @classmethod
    def parse(cls, raw: bytes):
        if len(raw) < CPU_SIZE:
            return None
        if raw[0] != CPU_REASON:
            return None
        try:
            f = struct.unpack_from(CPU_FMT, raw, 0)
        except struct.error:
            return None

        o              = cls()
        o.switch_id    = f[1]
        o.ingress_port = (f[2] & 0xFF80) >> 7
        o.sender_ip    = socket.inet_ntoa(f[3])
        o.sender_mac   = ":".join(f"{b:02x}" for b in f[4])
        o.target_ip    = socket.inet_ntoa(f[5])
        o.opcode       = f[6]
        o.reg_total    = f[7]
        o.reg_req      = f[8]
        o.reg_rep      = f[9]
        o.reg_grat     = f[10]
        o.reg_bcast    = f[11]
        o.reg_ctr      = f[12]
        return o

    def __repr__(self):
        return (f"<CPU sw={self.switch_id} "
                f"total={self.reg_total} req={self.reg_req} rep={self.reg_rep} "
                f"src={self.sender_ip}>")


# ── Window Aggregator ─────────────────────────────────────────────────────────
class WindowAggregator:
    def __init__(self, window_sec, dataset_path, label_mode):
        self.window_sec   = window_sec
        self.dataset_path = dataset_path
        self.label_mode   = label_mode
        self.lock         = threading.Lock()
        self._ip_mac_seen  = {}
        self._prev_src_ips = set()
        self.total_pkts_seen = 0
        self.total_pkts_dropped = 0
        self._reset()
        self._init_csv()

    def _reset(self):
        self.agg_total  = 0
        self.agg_req    = 0
        self.agg_rep    = 0
        self.agg_grat   = 0
        self.agg_bcast  = 0
        self.sip_list   = []
        self.smac_list  = []
        self.tip_list   = []
        self.n_packetin = 0
        self.win_start  = time.time()

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)
        write_hdr = not os.path.exists(self.dataset_path)
        self._f = open(self.dataset_path, "a", newline="")
        self._w = csv.writer(self._f)
        if write_hdr:
            self._w.writerow([
                "timestamp",
                "arp_total", "arp_request_count", "arp_reply_count",
                "req_reply_ratio", "gratuitous_arp_count",
                "broadcast_count", "packet_rate",
                "request_rate", "reply_rate",
                "src_ip_entropy", "src_mac_entropy", "target_ip_entropy",
                "unique_src_ip_count", "unique_src_mac_count",
                "top1_ip_share", "digest_sample_count",
                "ip_mac_consistency_score", "new_ip_ratio",
                "label",
            ])
            self._f.flush()
        log.info(f"[CSV] {self.dataset_path}")

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())

    def ingest(self, h: CpuHeader):
        with self.lock:
            self.agg_total  += h.reg_total
            self.agg_req    += h.reg_req
            self.agg_rep    += h.reg_rep
            self.agg_grat   += h.reg_grat
            self.agg_bcast  += h.reg_bcast
            self.sip_list.append(h.sender_ip)
            self.smac_list.append(h.sender_mac)
            self.tip_list.append(h.target_ip)
            self.n_packetin += 1
            self.total_pkts_seen += 1

    def note_drop(self, n=1):
        with self.lock:
            self.total_pkts_dropped += n

    def tick(self):
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                self._flush()
                self._reset()

    def _flush(self):
        elapsed = max(time.time() - self.win_start, 0.001)

        f1  = self.agg_total
        f2  = self.agg_req
        f3  = self.agg_rep
        f4  = round(f2 / (f3 + 1), 4)
        f5  = self.agg_grat
        f6  = self.agg_bcast
        f7  = round(f1 / elapsed, 4)
        f8  = round(f2 / elapsed, 4)
        f9  = round(f3 / elapsed, 4)

        f10 = round(self._entropy(self.sip_list),  4)
        f11 = round(self._entropy(self.smac_list), 4)
        f12 = round(self._entropy(self.tip_list),  4)

        usip  = set(self.sip_list)
        usmac = set(self.smac_list)
        f13 = len(usip)
        f14 = len(usmac)

        if self.sip_list:
            top1 = collections.Counter(self.sip_list).most_common(1)[0][1]
            f15  = round(top1 / len(self.sip_list), 4)
        else:
            f15  = 0.0

        f16 = self.n_packetin

        score = 0
        for ip, mac in zip(self.sip_list, self.smac_list):
            if ip not in self._ip_mac_seen:
                self._ip_mac_seen[ip] = set()
            before = len(self._ip_mac_seen[ip])
            self._ip_mac_seen[ip].add(mac)
            if len(self._ip_mac_seen[ip]) > before > 0:
                score += 1
        f17 = score

        if usip:
            f18 = round(len(usip - self._prev_src_ips) / len(usip), 4)
        else:
            f18 = 0.0
        self._prev_src_ips = usip.copy()

        label = 1 if self.label_mode == "attack" else 0
        ts    = datetime.now().isoformat(timespec="seconds")

        self._w.writerow([
            ts,
            f1, f2, f3, f4, f5, f6, f7, f8, f9,
            f10, f11, f12, f13, f14, f15, f16, f17, f18,
            label,
        ])
        self._f.flush()

        log.info(
            f"[WIN] {ts} | "
            f"total={f1:5d} req={f2:4d} rep={f3:4d} "
            f"rate={f7:7.1f}pps | "
            f"srcs={f13:3d} ent={f10:.3f} "
            f"mac_score={f17:3d} new_ip={f18:.3f} | "
            f"label={'ATTACK' if label else 'normal'} | "
            f"seen={self.total_pkts_seen} dropped={self.total_pkts_dropped}"
        )

    def set_label(self, mode):
        with self.lock:
            self.label_mode = mode
        log.info(f"[LABEL] → {mode}")

    def close(self):
        with self.lock:
            if self.n_packetin > 0:
                self._flush()
        self._f.close()
        log.info("[CTRL] CSV closed.")


# ── Raw AF_PACKET capture ─────────────────────────────────────────────────────
_agg: WindowAggregator = None


def _open_raw_socket(iface: str):
    """
    Open an AF_PACKET SOCK_RAW socket bound to `iface` with ETH_P_ALL so that
    EVERY ethertype (including BMv2's custom CPU frames) is delivered.

    Returns the socket on success, None on failure.
    """
    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        # Grow the kernel receive buffer so bursts don't overflow.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
        except OSError:
            pass  # not fatal
        s.bind((iface, ETH_P_ALL))
        s.setblocking(False)
        return s
    except OSError as e:
        # 19 = ENODEV, 100 = ENETDOWN
        log.debug(f"[SNIFF] {iface} open failed errno={e.errno}: {e}")
        return None


def _sniff_thread(iface: str):
    """
    Per-interface capture loop:
      1. Try to open the raw socket; if the veth isn't there yet, wait and retry.
      2. Once open, recvfrom() every frame, parse the CPU header from byte 0,
         and feed it to the aggregator.
      3. On any error, close and reopen — handles Mininet restarts transparently.
    """
    announced_wait = False

    while not SHUTDOWN.is_set():
        sock = _open_raw_socket(iface)
        if sock is None:
            if not announced_wait:
                log.info(f"[SNIFF] Waiting for {iface} to become available...")
                announced_wait = True
            if SHUTDOWN.wait(IFACE_RETRY_SEC):
                return
            continue

        announced_wait = False
        log.info(f"[SNIFF] Capturing on {iface} (ETH_P_ALL, rcvbuf={SO_RCVBUF_BYTES})")

        try:
            while not SHUTDOWN.is_set():
                # Wait up to 0.5s for data, then loop so we can check SHUTDOWN.
                r, _, _ = select.select([sock], [], [], 0.5)
                if not r:
                    continue

                # Drain everything currently queued. This is important under
                # high packet rates — doing one recv per select() call can
                # bottleneck and cause kernel-side drops.
                while True:
                    try:
                        raw, _addr = sock.recvfrom(RECV_BUF_SIZE)
                    except BlockingIOError:
                        break
                    except OSError as e:
                        raise  # bubble up to outer handler

                    if not raw:
                        continue

                    h = CpuHeader.parse(raw)
                    if h is not None:
                        _agg.ingest(h)
                    # else: not one of ours (e.g. stray frame) — ignore silently

        except OSError as e:
            log.warning(f"[SNIFF] {iface} lost (errno={e.errno}): {e}. Reconnecting...")
        except Exception as e:
            log.warning(f"[SNIFF] {iface} error: {e}. Reconnecting...")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if SHUTDOWN.wait(IFACE_RETRY_SEC):
            return


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global _agg

    ap = argparse.ArgumentParser(description="ARP Flood Detection Controller")
    ap.add_argument("--interfaces", "-i", nargs="+", required=True)
    ap.add_argument("--window",  "-w", type=int, default=WINDOW_SEC)
    ap.add_argument("--label",   "-l",
                    choices=["normal", "attack"], default="normal",
                    help="normal => label 0 in CSV, attack => label 1 in CSV")
    ap.add_argument("--dataset", "-d", default=DATASET_PATH)
    args = ap.parse_args()

    if os.geteuid() != 0:
        log.error("This controller needs root (AF_PACKET requires CAP_NET_RAW).")
        sys.exit(1)

    log.info("=" * 64)
    log.info("  ARP Flood Detection Controller")
    log.info(f"  Interfaces : {args.interfaces}")
    log.info(f"  Window     : {args.window}s")
    log.info(f"  Label      : {args.label}  "
             f"(csv value = {1 if args.label == 'attack' else 0}, "
             f"SIGUSR1 to toggle)")
    log.info(f"  Dataset    : {args.dataset}")
    log.info("=" * 64)

    _agg = WindowAggregator(args.window, args.dataset, args.label)

    threads = []
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,),
                             name=f"sniff-{iface}", daemon=True)
        t.start()
        threads.append(t)

    # Window ticker
    def _ticker():
        while not SHUTDOWN.is_set():
            if SHUTDOWN.wait(0.5):
                return
            _agg.tick()
    threading.Thread(target=_ticker, name="ticker", daemon=True).start()

    # SIGUSR1 toggles label
    def _toggle(sig, frame):
        _agg.set_label("attack" if _agg.label_mode == "normal" else "normal")
    signal.signal(signal.SIGUSR1, _toggle)

    log.info(f"[CTRL] PID={os.getpid()}  Running. Ctrl+C to stop.")
    try:
        while not SHUTDOWN.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("[CTRL] Shutting down...")
    finally:
        SHUTDOWN.set()
        # Give sniff threads a moment to exit cleanly
        for t in threads:
            t.join(timeout=1.0)
        _agg.close()


if __name__ == "__main__":
    main()