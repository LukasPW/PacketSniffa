import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import socket
import csv
import time
from collections import Counter, defaultdict, deque

# -----------------------------
# CONFIG
# -----------------------------
CSV_FILE = "packet_log.csv"
ALERT_FILE = "alerts.csv"
INTERFACE = None
CAPTURE_FILTER = "ip"

# Detection windows
RATE_WINDOW = 10
PORTSCAN_WINDOW = 10

# Thresholds
RATE_THRESHOLD = 300
SYN_THRESHOLD = 100
PORTSCAN_PORTS = 50

# Alert cooldown (seconds)
ALERT_COOLDOWN = 30

# Queue
INITIAL_QUEUE = 5000
MAX_QUEUE = 50000

# -----------------------------
# GLOBALS
# -----------------------------
packet_queue = queue.Queue(maxsize=INITIAL_QUEUE)

dns_cache = {}
packet_rate = defaultdict(deque)
syn_counter = defaultdict(deque)
port_counter = defaultdict(set)

alert_last_fired = {}
queue_lock = threading.Lock()
dynamic_queue_max = INITIAL_QUEUE

# -----------------------------
# CSV LOGGING
# -----------------------------
packet_csv = open(CSV_FILE, "w", newline="")
packet_writer = csv.writer(packet_csv)
packet_writer.writerow([
    "timestamp",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "packet_len",
    "tcp_flags",
    "is_private_dst",
    "is_multicast_dst",
    "suspicious"
])

alert_csv = open(ALERT_FILE, "w", newline="")
alert_writer = csv.writer(alert_csv)
alert_writer.writerow([
    "timestamp",
    "src_ip",
    "alert_type",
    "value"
])

# -----------------------------
# HELPERS
# -----------------------------
def now():
    return time.time()

def alert(src_ip, alert_type, value):
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
    if ip in dns_cache:
        return
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except:
        dns_cache[ip] = ip

# -----------------------------
# SECURITY ANALYSIS
# -----------------------------
def analyze(packet, src_ip, dst_port):
    t = now()

    # Packet rate
    pr = packet_rate[src_ip]
    pr.append(t)
    while pr and t - pr[0] > RATE_WINDOW:
        pr.popleft()

    if len(pr) > RATE_THRESHOLD:
        alert(src_ip, "HIGH_PACKET_RATE", len(pr))

    # TCP-specific
    if TCP in packet:
        flags = packet[TCP].flags

        if flags & 0x02:  # SYN
            sc = syn_counter[src_ip]
            sc.append(t)
            while sc and t - sc[0] > RATE_WINDOW:
                sc.popleft()

            if len(sc) > SYN_THRESHOLD:
                alert(src_ip, "SYN_FLOOD", len(sc))

            # Port scan detection
            pc = port_counter[src_ip]
            pc.add(dst_port)

            if len(pc) > PORTSCAN_PORTS:
                alert(src_ip, "PORT_SCAN", len(pc))

# -----------------------------
# PACKET WORKER
# -----------------------------
def packet_worker():
    global dynamic_queue_max

    while True:
        packet = packet_queue.get()
        if packet is None:
            break

        if IP not in packet:
            packet_queue.task_done()
            continue

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

        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore")

        resolve_dns(dst_ip)

        suspicious = 0
        analyze(packet, src_ip, dst_port)

        if any(
            k[0] == src_ip and now() - v < ALERT_COOLDOWN
            for k, v in alert_last_fired.items()
        ):
            suspicious = 1

        is_private = int(dst_ip.startswith(("10.", "172.16.", "192.168.")))
        is_multicast = int(dst_ip.startswith("239.") or dst_ip == "255.255.255.255")

        packet_writer.writerow([
            ts,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            pkt_len,
            flags,
            is_private,
            is_multicast,
            suspicious
        ])

        packet_queue.task_done()

        # Dynamic queue resizing
        with queue_lock:
            qsize = packet_queue.qsize()
            if qsize > dynamic_queue_max * 0.8:
                dynamic_queue_max = min(dynamic_queue_max * 2, MAX_QUEUE)
                packet_queue.maxsize = dynamic_queue_max
            elif qsize < dynamic_queue_max * 0.2:
                dynamic_queue_max = max(dynamic_queue_max // 2, INITIAL_QUEUE)
                packet_queue.maxsize = dynamic_queue_max

# -----------------------------
# SNIFF LOOP
# -----------------------------
def enqueue_packet(packet):
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass

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
