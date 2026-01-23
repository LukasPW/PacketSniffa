import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
import socket
import csv
import time
from collections import Counter, defaultdict

# -----------------------------
# CONFIG
# -----------------------------
CSV_FILE = "packet_log.csv"
INTERFACE = None
CAPTURE_FILTER = "ip"

# Security thresholds
RATE_WINDOW = 10
RATE_THRESHOLD = 300
SYN_THRESHOLD = 100
SHORT_CONN_THRESHOLD = 150

# Multicast/broadcast suppression
SUPPRESSION_INTERVAL = 5      # seconds
SUPPRESSION_MAX = 2           # max packets per interval

# -----------------------------
# GLOBALS
# -----------------------------
packet_queue = queue.Queue(maxsize=5000)  # initial size
stats = Counter()
ip_counter = Counter()
host_traffic = Counter()
dns_cache = {}
packet_rate = defaultdict(list)
syn_counter = Counter()
fin_counter = Counter()
security_warnings = set()

# Suppression tracking
last_seen = {}  # last timestamp per IP
suppression_count = defaultdict(int)

# Queue dynamic resizing
queue_lock = threading.Lock()
dynamic_queue_max = 5000

# -----------------------------
# LOGGING
# -----------------------------

csvfile = open(CSV_FILE, "w", newline="")
csv_writer = csv.writer(csvfile)
csv_writer.writerow([
    "timestamp","protocol","src_ip","src_port",
    "dst_ip","dst_port","flags","destination"
])

# -----------------------------
# DNS RESOLUTION
# -----------------------------
def resolve_destination(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except:
        dns_cache[ip] = ip
    return dns_cache[ip]

def classify_destination_with_comment(ip):
    comment = ""
    if ip.startswith("239."):
        comment = " (MULTICAST)"
    elif ip == "255.255.255.255":
        comment = " (BROADCAST)"
    elif ip.startswith(("10.","172.16.","192.168.")):
        comment = " (PRIVATE LAN)"
    return f"{resolve_destination(ip)}{comment}"

# -----------------------------
# SECURITY ANALYSIS
# -----------------------------
def analyze_security(packet, src_ip):
    now = time.time()
    packet_rate[src_ip].append(now)
    packet_rate[src_ip] = [t for t in packet_rate[src_ip] if now - t <= RATE_WINDOW]

    if len(packet_rate[src_ip]) > RATE_THRESHOLD:
        security_warnings.add(f"High traffic rate from {src_ip}")

    if TCP in packet:
        flags = packet[TCP].flags
        if flags == "S":
            syn_counter[src_ip] += 1
        if "F" in flags:
            fin_counter[src_ip] += 1
        if syn_counter[src_ip] > SYN_THRESHOLD and fin_counter[src_ip] < syn_counter[src_ip] // 2:
            security_warnings.add(f"SYN-heavy behavior from {src_ip}")
        if syn_counter[src_ip] + fin_counter[src_ip] > SHORT_CONN_THRESHOLD:
            security_warnings.add(f"High short-lived TCP connection churn from {src_ip}")

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

        timestamp = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        stats["total"] += 1
        ip_counter[src_ip] += 1
        host_traffic[dst_ip] += 1

        # DNS caching
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore").rstrip(".")

        # Security analysis
        analyze_security(packet, src_ip)

        # Rate-limited suppression for chatty destinations
        dst_comment = ""
        if dst_ip.startswith("239."):
            dst_comment = "MULTICAST"
        elif dst_ip == "255.255.255.255":
            dst_comment = "BROADCAST"
        elif dst_ip.startswith(("10.","172.16.","192.168.")):
            dst_comment = "PRIVATE LAN"

        now_time = time.time()
        if dst_comment:
            last_time, count = last_seen.get(dst_ip, (0,0))
            if now_time - last_time > SUPPRESSION_INTERVAL:
                # Reset interval
                last_seen[dst_ip] = (now_time, 1)
            else:
                if count >= SUPPRESSION_MAX:
                    packet_queue.task_done()
                    continue
                else:
                    last_seen[dst_ip] = (last_time, count + 1)

        # Protocol classification
        protocol, src_port, dst_port, flags = "OTHER", "", "", ""
        if TCP in packet:
            protocol = "TCP"
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            flags = packet[TCP].flags
        elif UDP in packet:
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport
            protocol = "QUIC" if packet[UDP].sport==443 or packet[UDP].dport==443 else "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        destination = classify_destination_with_comment(dst_ip)
        message = f"[{timestamp}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} FLAGS={flags} DEST={destination}"
        print(message)
        packet_len = len(packet)

        is_private = int(dst_ip.startswith(("10.","172.16.","192.168.")))
        is_multicast = int(dst_ip.startswith("239.") or dst_ip == "255.255.255.255")

        csv_writer.writerow([
            timestamp,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            int(flags) if flags != "" else 0,
            packet_len,
            is_private,
            is_multicast
        ])


        packet_queue.task_done()

        # Dynamic queue resizing
        with queue_lock:
            if packet_queue.qsize() > dynamic_queue_max * 0.8:
                dynamic_queue_max = min(dynamic_queue_max * 2, 50000)
                packet_queue.maxsize = dynamic_queue_max
            elif packet_queue.qsize() < dynamic_queue_max * 0.2:
                dynamic_queue_max = max(dynamic_queue_max // 2, 5000)
                packet_queue.maxsize = dynamic_queue_max

# -----------------------------
# SNIFF LOOP
# -----------------------------
def enqueue_packet(packet):
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass  # drop only if queue full

worker_thread = threading.Thread(target=packet_worker, daemon=True)
worker_thread.start()

print("Packet sniffer running...")
print(f"Text log: {LOG_FILE}") 
print(f"CSV log: {CSV_FILE}") 
print("Press CTRL+C to stop.\n")
try:
    sniff(iface=INTERFACE, filter=CAPTURE_FILTER, prn=enqueue_packet, store=False)
except KeyboardInterrupt:
    packet_queue.put(None)
    worker_thread.join()
    csvfile.close()
