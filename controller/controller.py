#!/usr/bin/env python3
"""
controller.py — ARP Flood Detection Controller
================================================
Receives PacketIn messages from all 20 switches via CPU veth interfaces.
No Thrift polling — switches push all data with every 10th ARP packet.

PacketIn structure (from switch):
    [cpu_header 41 bytes][ethernet 14 bytes][arp 28 bytes]

cpu_header carries:
    - reason, switch_id, ingress_port
    - sender_ip, sender_mac, target_ip, opcode   (ARP metadata)
    - reg_arp_total, reg_arp_request, reg_arp_reply,
      reg_gratuitous, reg_broadcast, reg_sample_counter  (register snapshot)

Every 3 seconds: aggregate all received PacketIn → compute 18 features → CSV.

USAGE:
    # Normal traffic (label=0):
    python3 controller.py --interfaces s1-cpu1 s2-cpu1 ... s20-cpu1 --label normal

    # Attack traffic (label=1):
    python3 controller.py --interfaces s1-cpu1 s2-cpu1 ... s20-cpu1 --label attack

    # Toggle label at runtime without restart:
    kill -USR1 <pid>
"""

import os, sys, time, struct, math, socket
import threading, collections, csv, logging, argparse, signal
from datetime import datetime

from scapy.all import sniff, conf
conf.verb = 0   # suppress scapy output

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
WINDOW_SEC   = 3
CPU_REASON   = 0xAA
DATASET_PATH = "/opt/p4work/arp_flood_detection/dataset/arp_dataset.csv"

# ── CPU Header parser ─────────────────────────────────────────────────────────
# Must match cpu_header_t in arp_monitor.p4 exactly.
#
# Field layout (network byte order):
#   reason          : 1 byte   offset 0
#   switch_id       : 1 byte   offset 1
#   ingress_port+pad: 2 bytes  offset 2  (9-bit port in top bits, 7-bit pad)
#   sender_ip       : 4 bytes  offset 4
#   sender_mac      : 6 bytes  offset 8
#   target_ip       : 4 bytes  offset 14
#   opcode          : 2 bytes  offset 18
#   reg_arp_total   : 4 bytes  offset 20
#   reg_arp_request : 4 bytes  offset 24
#   reg_arp_reply   : 4 bytes  offset 28
#   reg_gratuitous  : 4 bytes  offset 32
#   reg_broadcast   : 4 bytes  offset 36
#   reg_sample_ctr  : 1 byte   offset 40
#   TOTAL           : 41 bytes
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
        """Parse raw bytes into CpuHeader. Returns None if invalid."""
        if len(raw) < CPU_SIZE:
            return None
        if raw[0] != CPU_REASON:
            return None
        try:
            f = struct.unpack_from(CPU_FMT, raw, 0)
        except struct.error:
            return None

        o              = cls()
        # f[0] = reason (already checked)
        o.switch_id    = f[1]
        # ingress_port is 9 bits packed into the high bits of the 2-byte field
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
    """
    Collects PacketIn data from all switches.
    Every WINDOW_SEC: compute 18 features → append to CSV.
    Thread-safe via lock.
    """

    def __init__(self, window_sec, dataset_path, label_mode):
        self.window_sec   = window_sec
        self.dataset_path = dataset_path
        self.label_mode   = label_mode
        self.lock         = threading.Lock()
        # Cross-window state for features 17 and 18
        self._ip_mac_seen  = {}   # ip → set of MACs seen ever
        self._prev_src_ips = set()
        self._reset()
        self._init_csv()

    def _reset(self):
        self.agg_total    = 0
        self.agg_req      = 0
        self.agg_rep      = 0
        self.agg_grat     = 0
        self.agg_bcast    = 0
        self.sip_list     = []   # sender IPs  per PacketIn
        self.smac_list    = []   # sender MACs per PacketIn
        self.tip_list     = []   # target IPs  per PacketIn
        self.n_packetin   = 0    # total PacketIn received this window
        self.win_start    = time.time()

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)
        write_hdr = not os.path.exists(self.dataset_path)
        self._f = open(self.dataset_path, "a", newline="")
        self._w = csv.writer(self._f)
        if write_hdr:
            self._w.writerow([
                "timestamp",
                # Counter features (1-9)
                "arp_total", "arp_request_count", "arp_reply_count",
                "req_reply_ratio", "gratuitous_arp_count",
                "broadcast_count", "packet_rate",
                "request_rate", "reply_rate",
                # Digest features (10-16)
                "src_ip_entropy", "src_mac_entropy", "target_ip_entropy",
                "unique_src_ip_count", "unique_src_mac_count",
                "top1_ip_share", "digest_sample_count",
                # Anomaly features (17-18)
                "ip_mac_consistency_score", "new_ip_ratio",
                # Label
                "label",
            ])
            self._f.flush()
        log.info(f"[CSV] {self.dataset_path}")

    @staticmethod
    def _entropy(items):
        """Shannon entropy of a list of hashable items."""
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())

    def ingest(self, h: CpuHeader):
        """Called per PacketIn. Thread-safe."""
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

    def tick(self):
        """Called every ~0.5s. Flushes window when time is up."""
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                self._flush()
                self._reset()

    def _flush(self):
        """Compute all 18 features and write one CSV row. Must hold lock."""
        elapsed = max(time.time() - self.win_start, 0.001)

        # ── Features 1–9: counter-based ──────────────────────────────────────
        f1  = self.agg_total
        f2  = self.agg_req
        f3  = self.agg_rep
        f4  = round(f2 / (f3 + 1), 4)              # req_reply_ratio
        f5  = self.agg_grat
        f6  = self.agg_bcast
        f7  = round(f1 / elapsed, 4)                # packet_rate (pps)
        f8  = round(f2 / elapsed, 4)                # request_rate
        f9  = round(f3 / elapsed, 4)                # reply_rate

        # ── Features 10–16: digest-based ─────────────────────────────────────
        f10 = round(self._entropy(self.sip_list),   4)  # src_ip_entropy
        f11 = round(self._entropy(self.smac_list),  4)  # src_mac_entropy
        f12 = round(self._entropy(self.tip_list),   4)  # target_ip_entropy

        usip  = set(self.sip_list)
        usmac = set(self.smac_list)
        f13 = len(usip)                             # unique_src_ip_count
        f14 = len(usmac)                            # unique_src_mac_count

        if self.sip_list:
            top1 = collections.Counter(self.sip_list).most_common(1)[0][1]
            f15  = round(top1 / len(self.sip_list), 4)  # top1_ip_share
        else:
            f15  = 0.0

        f16 = self.n_packetin                       # digest_sample_count

        # ── Feature 17: ip_mac_consistency_score ─────────────────────────────
        # Count IPs that appear with a MAC they haven't used before.
        # Positive value = IP-MAC mapping is changing = spoofing indicator.
        score = 0
        for ip, mac in zip(self.sip_list, self.smac_list):
            if ip not in self._ip_mac_seen:
                self._ip_mac_seen[ip] = set()
            before = len(self._ip_mac_seen[ip])
            self._ip_mac_seen[ip].add(mac)
            after  = len(self._ip_mac_seen[ip])
            if after > before > 0:   # new MAC for a previously-seen IP
                score += 1
        f17 = score

        # ── Feature 18: new_ip_ratio ──────────────────────────────────────────
        # Fraction of this window's source IPs not seen in previous window.
        if usip:
            new_ips = usip - self._prev_src_ips
            f18 = round(len(new_ips) / len(usip), 4)
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
            f"label={'ATTACK' if label else 'normal'}"
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


# ── Packet sniffing ───────────────────────────────────────────────────────────
_agg: WindowAggregator = None

def _on_packet(pkt):
    try:
        raw = bytes(pkt)
        h   = CpuHeader.parse(raw)
        if h is not None:
            log.debug(repr(h))
            _agg.ingest(h)
    except Exception as e:
        log.debug(f"[PKT] error: {e}")

def _sniff_thread(iface):
    log.info(f"[SNIFF] {iface}")
    sniff(iface=iface, prn=_on_packet, store=False)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global _agg

    ap = argparse.ArgumentParser(description="ARP Flood Detection Controller")
    ap.add_argument("--interfaces", "-i", nargs="+", required=True,
                    help="CPU veth interfaces to sniff (sN-cpu1 for each switch)")
    ap.add_argument("--window",  "-w", type=int,   default=WINDOW_SEC)
    ap.add_argument("--label",   "-l",
                    choices=["normal", "attack"], default="normal",
                    help="Label for CSV rows: normal=0, attack=1")
    ap.add_argument("--dataset", "-d", default=DATASET_PATH)
    args = ap.parse_args()

    log.info("=" * 64)
    log.info("  ARP Flood Detection Controller")
    log.info(f"  Interfaces : {args.interfaces}")
    log.info(f"  Window     : {args.window}s")
    log.info(f"  Label      : {args.label}  (SIGUSR1 to toggle)")
    log.info(f"  Dataset    : {args.dataset}")
    log.info("=" * 64)

    _agg = WindowAggregator(args.window, args.dataset, args.label)

    # One sniff thread per CPU interface
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
        t.start()

    # Window ticker (fires every 0.5s, flushes when window expires)
    def _ticker():
        while True:
            time.sleep(0.5)
            _agg.tick()
    threading.Thread(target=_ticker, daemon=True).start()

    # SIGUSR1 toggles label between normal/attack without restarting
    def _toggle(sig, frame):
        _agg.set_label("attack" if _agg.label_mode == "normal" else "normal")
    signal.signal(signal.SIGUSR1, _toggle)

    log.info(f"[CTRL] PID={os.getpid()}  Running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("[CTRL] Shutting down...")
    finally:
        _agg.close()


if __name__ == "__main__":
    main()
