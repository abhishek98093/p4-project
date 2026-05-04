#!/usr/bin/env python3
"""
controller_new.py — ARP Flood Detection Controller (per-window stats)
======================================================================
Captures P4/BMv2 CPU-header digests via raw AF_PACKET sockets and writes
per-window features to CSV.

Per-process metrics logged (this PID only, never system-wide):
  cpu_load               : % of one logical CPU (0-100), normalised by cores
  ctx_voluntary          : voluntary   context-switch delta this window
  ctx_involuntary        : involuntary context-switch delta this window
  mem_rss_bytes          : resident set size at flush (bytes)
  digest_latency_mean_us : mean per-digest parse+ingest wall-time (µs)
  digest_latency_max_us  : max  per-digest parse+ingest wall-time (µs)
  iat_mean_ms            : mean inter-digest arrival time (ms)
  iat_min_ms             : min  inter-digest arrival time (ms)
  iat_std_ms             : std  inter-digest arrival time (ms)
  window_buf_depth       : digests buffered at flush (queue-depth proxy)
  flush_duration_ms      : wall-time to compute all features (ms)

USAGE:
    sudo python3 controller_new.py \
        --interfaces s1-cpu1 s2-cpu1 s11-cpu1 \
        --label normal

    sudo python3 controller_new.py \
        --interfaces s1-cpu1 s2-cpu1 s11-cpu1 \
        --label attack

    kill -USR1 <pid>     # toggle label at runtime
"""

import os, sys, time, struct, math, socket, select, statistics
import threading, collections, csv, logging, argparse, signal
from datetime import datetime

# ── psutil — per-process handle, initialised at import time ──────────────────
_HAS_PSUTIL = False
_PROC       = None          # psutil.Process for THIS pid only
_N_CORES    = 1
_ctx_last   = None          # baseline for context-switch deltas

try:
    import psutil
    _HAS_PSUTIL = True
    _PROC       = psutil.Process(os.getpid())
    _N_CORES    = psutil.cpu_count() or 1
    # Prime cpu_percent — first call always returns 0.0 (no prior reference).
    _PROC.cpu_percent(interval=None)
    # Snapshot context-switches so first delta in _flush() is accurate.
    _ctx_last = _PROC.num_ctx_switches()
    print(f"[INFO] psutil {psutil.__version__} loaded — per-process metrics active "
          f"(PID={os.getpid()}, cores={_N_CORES})")
except ImportError as e:
    print(f"[WARNING] psutil not installed: {e}")
except Exception as e:
    print(f"[WARNING] Error loading psutil: {e}")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/controller_new.log"),
    ]
)
log = logging.getLogger("ctrl")

if not _HAS_PSUTIL:
    log.warning("psutil not installed — performance columns will be -1.")
    log.warning("Install with: sudo pip3 install psutil")

# ── Config ────────────────────────────────────────────────────────────────────
WINDOW_SEC      = 3
CPU_REASON      = 0xAA
DATASET_PATH    = "/opt/p4work/arp_flood_detection/dataset/arp_dataset_new.csv"
IFACE_RETRY_SEC = 2
ETH_P_ALL       = 0x0003
RECV_BUF_SIZE   = 65535
SO_RCVBUF_BYTES = 16 * 1024 * 1024
SHUTDOWN        = threading.Event()

# Linux AF_PACKET stats socket option
SOL_PACKET        = 263
PACKET_STATISTICS = 6
TPACKET_STATS_FMT = "II"
TPACKET_STATS_LEN = struct.calcsize(TPACKET_STATS_FMT)   # 8 bytes

# ── CPU Header parser ─────────────────────────────────────────────────────────
CPU_FMT  = "!BB H 4s 6s 4s H IIIII B"
CPU_SIZE = struct.calcsize(CPU_FMT)   # 41 bytes


class CpuHeader:
    __slots__ = [
        "switch_id", "ingress_port",
        "sender_ip", "sender_mac", "target_ip", "opcode",
        "reg_total", "reg_req", "reg_rep",
        "reg_grat", "reg_bcast", "reg_ctr",
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


# ── Per-process metric helpers ────────────────────────────────────────────────

def _cpu_load() -> float:
    """
    CPU% used by THIS PROCESS, normalised to 0-100.
    Reads /proc/<pid>/stat (non-blocking, uses elapsed time since last call).
    """
    if not _HAS_PSUTIL or _PROC is None:
        return -1.0
    try:
        return round(_PROC.cpu_percent(interval=None) / _N_CORES, 2)
    except Exception:
        return -1.0


def _ctx_delta():
    """
    Returns (voluntary_delta, involuntary_delta) context-switches since
    the last call. Updates global _ctx_last. Returns (-1, -1) if unavailable.
    """
    global _ctx_last
    if not _HAS_PSUTIL or _PROC is None or _ctx_last is None:
        return -1, -1
    try:
        current   = _PROC.num_ctx_switches()
        vol_delta = current.voluntary   - _ctx_last.voluntary
        inv_delta = current.involuntary - _ctx_last.involuntary
        _ctx_last = current
        return max(vol_delta, 0), max(inv_delta, 0)
    except Exception:
        return -1, -1


def _rss_bytes() -> int:
    """Resident set size of this process in bytes. -1 if unavailable."""
    if not _HAS_PSUTIL or _PROC is None:
        return -1
    try:
        return _PROC.memory_info().rss
    except Exception:
        return -1


# ── PACKET_STATISTICS reader ──────────────────────────────────────────────────

def _read_packet_drops(sock) -> int:
    """
    Read kernel AF_PACKET drop counter (resets on every read).
    Returns tp_drops since last call, 0 on error.
    """
    try:
        data = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, TPACKET_STATS_LEN)
        _tp_packets, tp_drops = struct.unpack(TPACKET_STATS_FMT, data)
        return tp_drops
    except OSError:
        return 0


# ── Window Aggregator ─────────────────────────────────────────────────────────
class WindowAggregator:
    def __init__(self, window_sec, dataset_path, label_mode):
        self.window_sec    = window_sec
        self.dataset_path  = dataset_path
        self.label_mode    = label_mode
        self.lock          = threading.Lock()
        self._ip_mac_seen  = {}
        self._prev_src_ips = set()
        self._reset()
        self._init_csv()

        # Second cpu_percent prime after __init__ work has run,
        # so the baseline is fresh before the first real window flush.
        if _HAS_PSUTIL and _PROC is not None:
            log.info("Priming per-process CPU counter...")
            _PROC.cpu_percent(interval=None)
            time.sleep(0.3)
            log.info(f"Per-process CPU after prime: {_cpu_load()}%")

    # ── Window state ─────────────────────────────────────────────────────────

    def _reset(self):
        """Zero all per-window accumulators."""
        self.agg_total        = 0
        self.agg_req          = 0
        self.agg_rep          = 0
        self.agg_grat         = 0
        self.agg_bcast        = 0
        self.sip_list         = []
        self.smac_list        = []
        self.tip_list         = []
        self.n_packetin       = 0
        self.window_drops     = 0
        self.arrival_times    = []   # monotonic timestamp per digest (for IAT)
        self.digest_latencies = []   # parse+ingest wall-time per digest (µs)
        self.win_start        = time.time()

    # ── CSV ──────────────────────────────────────────────────────────────────

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)
        write_hdr = not os.path.exists(self.dataset_path)
        self._f = open(self.dataset_path, "a", newline="")
        self._w = csv.writer(self._f)
        if write_hdr:
            self._w.writerow([
                # ── existing ARP features ──────────────────────────────────
                "timestamp",
                "arp_total", "arp_request_count", "arp_reply_count",
                "req_reply_ratio", "gratuitous_arp_count",
                "broadcast_count", "packet_rate",
                "request_rate", "reply_rate",
                "src_ip_entropy", "src_mac_entropy", "target_ip_entropy",
                "unique_src_ip_count", "unique_src_mac_count",
                "top1_ip_share", "digest_sample_count",
                "ip_mac_consistency_score", "new_ip_ratio",
                # ── per-window process metrics ─────────────────────────────
                "digests_processed",       # digest count this window
                "packets_dropped",         # kernel AF_PACKET drops this window
                "cpu_load",                # % one logical CPU, this PID
                "ctx_voluntary",           # voluntary   ctx-switch delta
                "ctx_involuntary",         # involuntary ctx-switch delta
                "mem_rss_bytes",           # RSS of this process (bytes)
                "digest_latency_mean_us",  # mean parse+ingest time (µs)
                "digest_latency_max_us",   # max  parse+ingest time (µs)
                "iat_mean_ms",             # mean inter-digest arrival (ms)
                "iat_min_ms",              # min  inter-digest arrival (ms)
                "iat_std_ms",              # std  inter-digest arrival (ms)
                "window_buf_depth",        # digests in buffer at flush
                "flush_duration_ms",       # feature computation cost (ms)
                "label",
            ])
            self._f.flush()
        log.info(f"[CSV] {self.dataset_path}")

    # ── Ingest (called from sniff threads) ───────────────────────────────────

    def ingest(self, h: CpuHeader, arrival_ts: float):
        """
        Store digest features. arrival_ts is time.monotonic() recorded by the
        sniff thread BEFORE CpuHeader.parse() — so latency includes parse time.
        """
        latency_us = (time.monotonic() - arrival_ts) * 1e6
        with self.lock:
            self.agg_total  += h.reg_total
            self.agg_req    += h.reg_req
            self.agg_rep    += h.reg_rep
            self.agg_grat   += h.reg_grat
            self.agg_bcast  += h.reg_bcast
            self.sip_list.append(h.sender_ip)
            self.smac_list.append(h.sender_mac)
            self.tip_list.append(h.target_ip)
            self.arrival_times.append(arrival_ts)
            self.digest_latencies.append(latency_us)
            self.n_packetin += 1

    def note_drop(self, n=1):
        if n <= 0:
            return
        with self.lock:
            self.window_drops += n

    # ── Tick (called from ticker thread every 0.5s) ──────────────────────────

    def tick(self):
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                self._flush()
                self._reset()

    # ── Flush ────────────────────────────────────────────────────────────────

    def _flush(self):
        # ── Sample per-process metrics first (non-blocking kernel reads) ─────
        cpu_load           = _cpu_load()
        ctx_vol, ctx_invol = _ctx_delta()
        rss                = _rss_bytes()

        # ── Start timing feature computation ─────────────────────────────────
        t_flush_start = time.monotonic()

        elapsed = max(time.time() - self.win_start, 0.001)

        # ── Existing ARP features ─────────────────────────────────────────────
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
        f17 = round(1.0 - (score / (len(usip) + 1e-9)), 4) if usip else 1.0

        if usip:
            f18 = round(len(usip - self._prev_src_ips) / len(usip), 4)
        else:
            f18 = 0.0
        self._prev_src_ips = usip.copy()

        # ── Digest latency stats ──────────────────────────────────────────────
        lats = self.digest_latencies
        if lats:
            lat_mean = round(sum(lats) / len(lats), 2)
            lat_max  = round(max(lats), 2)
        else:
            lat_mean = lat_max = 0.0

        # ── Inter-digest arrival time stats ───────────────────────────────────
        times = self.arrival_times
        if len(times) >= 2:
            gaps_ms  = [(times[i+1] - times[i]) * 1000.0
                        for i in range(len(times) - 1)]
            iat_mean = round(sum(gaps_ms) / len(gaps_ms), 4)
            iat_min  = round(min(gaps_ms), 4)
            iat_std  = round(statistics.stdev(gaps_ms), 4) if len(gaps_ms) > 1 else 0.0
        else:
            iat_mean = iat_min = iat_std = 0.0

        buf_depth         = self.n_packetin
        digests_processed = self.n_packetin
        packets_dropped   = self.window_drops

        flush_duration_ms = round((time.monotonic() - t_flush_start) * 1000, 2)

        label = 1 if self.label_mode == "attack" else 0
        ts    = datetime.now().isoformat(timespec="seconds")

        # ── Write CSV row ─────────────────────────────────────────────────────
        self._w.writerow([
            ts,
            f1, f2, f3, f4, f5, f6, f7, f8, f9,
            f10, f11, f12, f13, f14, f15, f16, f17, f18,
            digests_processed, packets_dropped,
            cpu_load, ctx_vol, ctx_invol, rss,
            lat_mean, lat_max,
            iat_mean, iat_min, iat_std,
            buf_depth, flush_duration_ms,
            label,
        ])
        self._f.flush()

        log.info(
            f"[WIN] {ts} | "
            f"total={f1:5d} req={f2:4d} rep={f3:4d} rate={f7:7.1f}pps | "
            f"srcs={f13:3d} ent={f10:.3f} mac_score={f17:.3f} new_ip={f18:.3f} | "
            f"digests={digests_processed} drops={packets_dropped} buf={buf_depth} | "
            f"cpu={cpu_load:.1f}% ctx_vol={ctx_vol} ctx_invol={ctx_invol} "
            f"rss={rss//1024 if rss >= 0 else -1}KB | "
            f"lat_mean={lat_mean:.0f}us lat_max={lat_max:.0f}us | "
            f"iat_mean={iat_mean:.2f}ms iat_min={iat_min:.2f}ms iat_std={iat_std:.2f}ms | "
            f"flush={flush_duration_ms:.1f}ms | "
            f"label={'ATTACK' if label else 'normal'}"
        )

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())

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
    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
        except OSError:
            pass
        s.bind((iface, ETH_P_ALL))
        s.setblocking(False)
        return s
    except OSError as e:
        log.debug(f"[SNIFF] {iface} open failed errno={e.errno}: {e}")
        return None


def _sniff_thread(iface: str):
    """
    Per-interface capture loop.
    arrival_ts is stamped BEFORE CpuHeader.parse() so latency includes
    parse time + lock acquisition + list append inside ingest().
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

        # Prime PACKET_STATISTICS — discard drops that occurred before we started.
        _read_packet_drops(sock)

        try:
            while not SHUTDOWN.is_set():
                r, _, _ = select.select([sock], [], [], 0.5)

                if not r:
                    # Idle — still drain kernel drop counter so it doesn't
                    # accumulate silently between bursts.
                    drops = _read_packet_drops(sock)
                    if drops:
                        _agg.note_drop(drops)
                    continue

                # Drain all frames currently queued in the kernel ring.
                while True:
                    try:
                        raw, _addr = sock.recvfrom(RECV_BUF_SIZE)
                    except BlockingIOError:
                        break
                    except OSError:
                        raise

                    if not raw:
                        continue

                    # Stamp arrival BEFORE parse — latency includes parse cost.
                    arrival_ts = time.monotonic()
                    h = CpuHeader.parse(raw)
                    if h is not None:
                        _agg.ingest(h, arrival_ts)

                # After draining, read kernel drops for this batch.
                drops = _read_packet_drops(sock)
                if drops:
                    _agg.note_drop(drops)

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

    ap = argparse.ArgumentParser(
        description="ARP Flood Detection Controller (per-window stats)"
    )
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
    log.info("  ARP Flood Detection Controller — per-window stats")
    log.info(f"  Interfaces : {args.interfaces}")
    log.info(f"  Window     : {args.window}s")
    log.info(f"  Label      : {args.label}  "
             f"(csv value = {1 if args.label == 'attack' else 0}, "
             f"SIGUSR1 to toggle)")
    log.info(f"  Dataset    : {args.dataset}")
    log.info(f"  psutil     : {'yes — per-process only' if _HAS_PSUTIL else 'NO — all perf cols = -1'}")
    log.info(f"  cpu_load   : % of one logical CPU, this PID (0-100)")
    log.info("=" * 64)

    _agg = WindowAggregator(args.window, args.dataset, args.label)

    threads = []
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,),
                             name=f"sniff-{iface}", daemon=True)
        t.start()
        threads.append(t)

    def _ticker():
        while not SHUTDOWN.is_set():
            if SHUTDOWN.wait(0.5):
                return
            _agg.tick()
    threading.Thread(target=_ticker, name="ticker", daemon=True).start()

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
        for t in threads:
            t.join(timeout=1.0)
        _agg.close()


if __name__ == "__main__":
    main()
