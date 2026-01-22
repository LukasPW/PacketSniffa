from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
from collections import Counter, defaultdict
import socket
import os
import sys
import csv
import time

# -----------------------------
# CONFIGURATION
# -----------------------------
LOG_FILE = "packet_log.txt"
CSV_FILE = "packet_log.csv"
INTERFACE = None
CAPTURE_FILTER = "ip"

# Security thresholds (tunable)
RATE_WINDOW = 10                 # seconds
RATE_THRESHOLD = 300             # packets per window
SYN_THRESHOLD = 100              # SYN packets without FIN
SHORT_CONN_THRESHOLD = 150       # high churn indicator

# -----------------------------
# GLOBAL STATS
# -----------------------------
stats = Counter()
ip_counter = Counter()
host_traffic = Counter()
dns_cache = {}

# Security tracking
packet_rate = defaultdict(list)     # IP -> timestamps
syn_counter = Counter()
fin_counter = Counter()
security_warnings = set()

# -----------------------------
# LOG FILE (REFRESH PER SESSION)
# -----------------------------
def init_text_log():
    with open(LOG_FILE, "w") as f:
        f.write("=== New Capture Session ===\n")

init_text_log()

# -----------------------------
# CSV FILE (HEADERS)
# -----------------------------
with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp","protocol","src_ip","src_port",
        "dst_ip","dst_port","flags","destination"
    ])

csvfile = open(CSV_FILE, "a", newline="")
csv_writer = csv.writer(csvfile)

# -----------------------------
# LOGGING
# -----------------------------
def log_to_file(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

# -----------------------------
# DNS HANDLING
# -----------------------------
def handle_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        for i in range(packet[DNS].ancount):
            ans = packet[DNS].an[i]
            if ans.type == 1:
                dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore").rstrip(".")

def resolve_destination(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# -----------------------------
# QUIC DETECTION
# -----------------------------
def is_quic(packet):
    return UDP in packet and (packet[UDP].sport == 443 or packet[UDP].dport == 443)

# -----------------------------
# SECURITY ANALYSIS
# -----------------------------
def analyze_security(packet, src_ip):
    now = time.time()
    packet_rate[src_ip].append(now)

    # Sliding window cleanup
    packet_rate[src_ip] = [
        t for t in packet_rate[src_ip] if now - t <= RATE_WINDOW
    ]

    if len(packet_rate[src_ip]) > RATE_THRESHOLD:
        security_warnings.add(
            f"High traffic rate from {src_ip} (> {RATE_THRESHOLD}/{RATE_WINDOW}s)"
        )

    if TCP in packet:
        flags = packet[TCP].flags
        if flags == "S":
            syn_counter[src_ip] += 1
        if "F" in flags:
            fin_counter[src_ip] += 1

        if syn_counter[src_ip] > SYN_THRESHOLD and fin_counter[src_ip] < syn_counter[src_ip] // 2:
            security_warnings.add(
                f"SYN-heavy behavior from {src_ip} (scan-like pattern)"
            )

        if syn_counter[src_ip] + fin_counter[src_ip] > SHORT_CONN_THRESHOLD:
            security_warnings.add(
                f"High short-lived TCP connection churn from {src_ip}"
            )

# -----------------------------
# PACKET HANDLER
# -----------------------------
def packet_handler(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    stats["total"] += 1
    ip_counter[src_ip] += 1
    host_traffic[dst_ip] += 1

    handle_dns(packet)
    analyze_security(packet, src_ip)

    destination = resolve_destination(dst_ip)

    protocol = "OTHER"
    src_port = ""
    dst_port = ""
    flags = ""

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        message = f"[{timestamp}] TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} FLAGS={flags} DEST={destination}"

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "QUIC (likely)" if is_quic(packet) else "UDP"
        message = f"[{timestamp}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} DEST={destination}"

    elif ICMP in packet:
        protocol = "ICMP"
        message = f"[{timestamp}] ICMP {src_ip} -> {dst_ip}"

    else:
        message = f"[{timestamp}] OTHER {src_ip} -> {dst_ip}"

    print(message)
    log_to_file(message)
    csv_writer.writerow([timestamp, protocol, src_ip, src_port, dst_ip, dst_port, flags, destination])

# -----------------------------
# PER-HOST GRAPH
# -----------------------------
def print_host_graph():
    print("\nPer-Host Traffic Graph")
    print("======================")
    for host, count in host_traffic.most_common(10):
        name = resolve_destination(host)
        bar = "#" * min(count // 5, 50)
        print(f"{name:<40} | {bar} ({count})")

# -----------------------------
# SUMMARY
# -----------------------------
def print_summary():
    print("\nCapture Summary")
    print("================")
    for k, v in stats.items():
        print(f"{k.upper():<6}: {v}")

    print_host_graph()

    print("\nSecurity Observations")
    print("=====================")
    if not security_warnings:
        print("No significant anomalies observed.")
    else:
        for w in security_warnings:
            print("-", w)

# -----------------------------
# MAIN
# -----------------------------
print("Packet sniffer running...")
print(f"Text log: {LOG_FILE}")
print(f"CSV log: {CSV_FILE}")
print("Press CTRL+C to stop.\n")

try:
    sniff(
        iface=INTERFACE,
        filter=CAPTURE_FILTER,
        prn=packet_handler,
        store=False
    )
except KeyboardInterrupt:
    print_summary()
    csvfile.close()
    sys.exit(0)

# open terminal as admin and run : python sniffer.py
# to check if it works run: scapy, in terminal
