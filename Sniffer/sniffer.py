import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import socket
import csv
import time
from collections import Counter, defaultdict, deque

# -----------------------------
# CONFIGURATION
# -----------------------------
CSV_FILE = "packet_log.csv"         # main packet log
ALERT_FILE = "alerts.csv"           # IDS alert log
INTERFACE = None                     # sniffing interface (None = default)
CAPTURE_FILTER = "ip"                # BPF filter

# Detection windows
RATE_WINDOW = 10                     # seconds for high-rate detection
PORTSCAN_WINDOW = 10                 # seconds for port scan detection
SHORT_CONN_WINDOW = 60               # seconds for short-lived TCP detection

# Thresholds
RATE_THRESHOLD = 3000                # packets in RATE_WINDOW to trigger alert
SYN_THRESHOLD = 200                  # SYN packets in RATE_WINDOW to trigger SYN flood alert
PORTSCAN_PORTS = 100                 # unique dst ports to trigger port scan
SHORT_CONN_THRESHOLD = 50            # number of short-lived TCP connections per IP
HALF_OPEN_RATIO_THRESHOLD = 2        # SYN/FIN ratio for half-open alert

# Alert system
ALERT_COOLDOWN = 30                  # seconds before repeated alert for same IP/type

# Queue
INITIAL_QUEUE = 5000                 # starting queue size
MAX_QUEUE = 50000                     # max queue size under load

# -----------------------------
# GLOBALS
# -----------------------------
packet_queue = queue.Queue(maxsize=INITIAL_QUEUE)

# DNS cache for host resolution
dns_cache = {}

# Tier-1 data structures
packet_rate = defaultdict(deque)     # track packet timestamps per src_ip
syn_counter = defaultdict(deque)     # track SYN timestamps per src_ip
port_counter = defaultdict(set)      # track unique dst ports per src_ip
alert_last_fired = {}                # track last alert timestamp per (src_ip, alert_type)

# Tier-2 TCP tracking
tcp_connections = {}                 # key=(src_ip,dst_ip,dst_port), value=dict(syn, fin, start_time, state, last_seen)
short_conn_history = defaultdict(deque)  # track recent short-lived connections per src_ip

# Queue management
queue_lock = threading.Lock()
dynamic_queue_max = INITIAL_QUEUE

# -----------------------------
# CSV LOGGING
# -----------------------------
packet_csv = open(CSV_FILE, "w", newline="")
packet_writer = csv.writer(packet_csv)
packet_writer.writerow([
    "timestamp", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
    "packet_len", "tcp_flags", "is_private_dst", "is_multicast_dst", "suspicious"
])

alert_csv = open(ALERT_FILE, "w", newline="")
alert_writer = csv.writer(alert_csv)
alert_writer.writerow(["timestamp", "src_ip", "alert_type", "value"])

# -----------------------------
# HELPERS
# -----------------------------
def now():
    """Return current epoch time."""
    return time.time()

def alert(src_ip, alert_type, value):
    """
    Fire an alert if cooldown expired.
    Logs to console and CSV.
    """
    key = (src_ip, alert_type)
    last = alert_last_fired.get(key, 0)

    if now() - last < ALERT_COOLDOWN:
        return False

    alert_last_fired[key] = now()
    ts = datetime.now().isoformat()

    print(f"[ALERT] {ts} {src_ip} {alert_type} {value}")
    alert_writer.writerow([ts, src_ip, alert_type, value])
    return True

def resolve_dns(ip):
    """
    Resolve IP to hostname and cache.
    """
    if ip in dns_cache:
        return
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except:
        dns_cache[ip] = ip

# -----------------------------
# ANALYSIS FUNCTION (Tier1 + Tier2)
# -----------------------------
def analyze(packet, src_ip, dst_ip, dst_port):
    """
    Analyze a packet for:
      - Tier1: high packet rate, SYN flood, port scan
      - Tier2: TCP lifecycle, short-lived connections, half-open detection
    """
    # skip LAN/internal traffic to reduce false positives
    if src_ip.startswith(("10.", "172.16.", "192.168.")):
        return

    t = now()

    # -----------------------------
    # Tier1: Packet rate
    # -----------------------------
    pr = packet_rate[src_ip]
    pr.append(t)
    while pr and t - pr[0] > RATE_WINDOW:
        pr.popleft()
    if len(pr) > RATE_THRESHOLD:
        alert(src_ip, "HIGH_PACKET_RATE", len(pr))

    # -----------------------------
    # Tier1: TCP SYN flood / port scan
    # -----------------------------
    if TCP in packet:
        flags = packet[TCP].flags

        # track SYN flood
        if flags & 0x02:  # SYN
            sc = syn_counter[src_ip]
            sc.append(t)
            while sc and t - sc[0] > RATE_WINDOW:
                sc.popleft()
            if len(sc) > SYN_THRESHOLD:
                alert(src_ip, "SYN_FLOOD", len(sc))

            # port scan detection
            pc = port_counter[src_ip]
            pc.add(dst_port)
            if len(pc) > PORTSCAN_PORTS:
                alert(src_ip, "PORT_SCAN", len(pc))

    # -----------------------------
    # Tier2: TCP connection tracking
    # -----------------------------
    if TCP in packet:
        key = (src_ip, dst_ip, dst_port)
        conn = tcp_connections.get(key, {
            "syn":0, "fin":0, "start_time":t, "state":"CLOSED", "last_seen":t
        })
        flags = packet[TCP].flags

        # SYN packet -> start connection
        if flags & 0x02:
            conn["syn"] += 1
            conn["state"] = "SYN_SENT"
            conn["last_seen"] = t

        # FIN packet -> close connection
        if flags & 0x01:
            conn["fin"] += 1
            conn["state"] = "CLOSED"
            conn["last_seen"] = t
            duration = t - conn.get("start_time", t)
            short_conn_history[src_ip].append((t, duration))

        # RST packet -> abrupt close
        if flags & 0x04:
            conn["state"] = "CLOSED"
            conn["last_seen"] = t
            duration = t - conn.get("start_time", t)
            short_conn_history[src_ip].append((t, duration))

        # save connection
        tcp_connections[key] = conn

        # -----------------------------
        # Tier2: Short-lived connection alert
        # -----------------------------
        sh = short_conn_history[src_ip]
        # cleanup old entries
        while sh and t - sh[0][0] > SHORT_CONN_WINDOW:
            sh.popleft()
        if len(sh) > SHORT_CONN_THRESHOLD:
            alert(src_ip, "SHORT_LIVED_TCP", len(sh))

        # half-open SYN-heavy detection
        if conn["fin"] > 0:
            syn_fin_ratio = conn["syn"] / conn["fin"]
            if syn_fin_ratio >= HALF_OPEN_RATIO_THRESHOLD:
                alert(src_ip, "HALF_OPEN_TCP", syn_fin_ratio)

        short_conn_history[src_ip] = sh

# -----------------------------
# PACKET WORKER THREAD
# -----------------------------
def packet_worker():
    """
    Worker thread: processes packets from the queue.
    Handles DNS, analysis, CSV logging, and dynamic queue resizing.
    """
    global dynamic_queue_max

    while True:
        packet = packet_queue.get()
        if packet is None:
            break

        # skip non-IP packets
        if IP not in packet:
            packet_queue.task_done()
            continue

        # timestamp & basic info
        ts = datetime.now().isoformat()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)

        protocol = 0
        src_port = 0
        dst_port = 0
        flags = 0

        if TCP in packet:
            protocol = 6
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = int(packet[TCP].flags)
        elif UDP in packet:
            protocol = 17
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = 1

        # DNS caching
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore")

        resolve_dns(dst_ip)

        # -----------------------------
        # Analysis + auto-labeling
        # -----------------------------
        analyze(packet, src_ip, dst_ip, dst_port)

        # auto-label suspicious packets if any alert fired recently
        suspicious = 0
        for (ip, alert_type), alert_ts in alert_last_fired.items():
            if ip == src_ip and now() - alert_ts < ALERT_COOLDOWN:
                suspicious = 1
                break

        # destination flags
        is_private = int(dst_ip.startswith(("10.", "172.16.", "192.168.")))
        is_multicast = int(dst_ip.startswith("239.") or dst_ip == "255.255.255.255")

        # write CSV
        packet_writer.writerow([
            ts, protocol, src_ip, dst_ip, src_port, dst_port,
            pkt_len, flags, is_private, is_multicast, suspicious
        ])

        packet_queue.task_done()

        # -----------------------------
        # Dynamic queue resizing
        # -----------------------------
        with queue_lock:
            qsize = packet_queue.qsize()
            if qsize > dynamic_queue_max * 0.8:
                dynamic_queue_max = min(dynamic_queue_max * 2, MAX_QUEUE)
                packet_queue.maxsize = dynamic_queue_max
            elif qsize < dynamic_queue_max * 0.2:
                dynamic_queue_max = max(dynamic_queue_max // 2, INITIAL_QUEUE)
                packet_queue.maxsize = dynamic_queue_max

# -----------------------------
# PACKET ENQUEUE CALLBACK
# -----------------------------
def enqueue_packet(packet):
    """
    Called by Scapy sniff() per packet.
    Non-blocking enqueue; drops packets if queue is full.
    """
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass

# -----------------------------
# MAIN THREAD / SNIFFER
# -----------------------------
worker = threading.Thread(target=packet_worker, daemon=True)
worker.start()

print("IDS sniffer running")
print(f"Packets → {CSV_FILE}")
print(f"Alerts  → {ALERT_FILE}")

try:
    sniff(iface=INTERFACE, filter=CAPTURE_FILTER, prn=enqueue_packet, store=False)
except KeyboardInterrupt:
    packet_queue.put(None)
    worker.join()
    packet_csv.close()
    alert_csv.close()
