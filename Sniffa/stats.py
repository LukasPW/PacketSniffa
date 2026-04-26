"""
stats.py — shared live state between sniffer.py and ui.py

Both modules import this. sniffer.py writes; ui.py reads.
All structures are updated under their own locks where needed,
but since CPython's GIL makes simple int/deque ops atomic enough
for a dashboard, we only use an explicit lock for recent_alerts.
"""

import threading
import time
from collections import deque, defaultdict

# ── startup ────────────────────────────────────────────────────────────────
start_time   = time.time()
ml_enabled   = False          # flipped to True when model loads

# ── packet counters ────────────────────────────────────────────────────────
total_packets   = 0
dropped_packets = 0           # incremented when queue is full

# packets seen in last second -- used to compute live pkt/s in the UI
_rate_timestamps = deque()    # raw timestamps, pruned by ui.py each redraw

# ── protocol breakdown  (proto num → count) ────────────────────────────────
proto_counts: dict[int, int] = defaultdict(int)   # 6=TCP 17=UDP 1=ICMP 0=other

# ── top talkers  (src_ip → packet count) ───────────────────────────────────
top_talkers: dict[str, int] = defaultdict(int)

# ── geo / service breakdown ────────────────────────────────────────────────
country_counts: dict[str, int] = defaultdict(int)
service_counts: dict[str, int] = defaultdict(int)

# ── alerts  (thread-safe deque, capped at 200) ─────────────────────────────
alerts_lock   = threading.Lock()
recent_alerts: deque = deque(maxlen=200)
total_alerts  = 0

# ── queue depth (written by sniffer, read by ui) ───────────────────────────
queue_depth = 0
queue_max   = 1             # set to PACKET_QUEUE_MAX on sniffer init


def record_packet(src_ip: str, proto: int, country: str, service: str) -> None:
    """Called once per processed packet from the sniffer worker thread."""
    global total_packets
    total_packets += 1
    _rate_timestamps.append(time.time())
    proto_counts[proto]     += 1
    top_talkers[src_ip]     += 1
    country_counts[country] += 1
    service_counts[service] += 1


def record_alert(ts: str, src_ip: str, alert_type: str,
                 value: int, org: str, service: str) -> None:
    global total_alerts
    total_alerts += 1
    with alerts_lock:
        recent_alerts.appendleft({
            "ts":         ts,
            "src_ip":     src_ip,
            "type":       alert_type,
            "value":      value,
            "org":        org or "?",
            "service":    service or "?",
        })


def packets_per_second(window: float = 2.0) -> int:
    """Count packets timestamped within the last `window` seconds."""
    cutoff = time.time() - window
    # prune old entries from the left
    while _rate_timestamps and _rate_timestamps[0] < cutoff:
        _rate_timestamps.popleft()
    return int(len(_rate_timestamps) / window)

# ── live packet log (capped at 500) ───────────────────────────────────────
log_lock     = threading.Lock()
recent_packets: deque = deque(maxlen=500)

def record_log(ts: str, src_ip: str, dst_ip: str, proto: int,
               src_port: int, dst_port: int, country: str,
               service: str, pkt_len: int) -> None:
    with log_lock:
        recent_packets.appendleft({
            "ts":       ts,
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "proto":    proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "country":  country,
            "service":  service,
            "pkt_len":  pkt_len,
        })
