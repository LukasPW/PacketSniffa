import threading
import queue
import time
import csv
import socket
from datetime import datetime
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import geoip2.database
import pandas as pd
import joblib

# ============================================================
# CONFIG
# ============================================================

CSV_FILE = "packet_log.csv"
ALERT_FILE = "alerts.csv"
INTERFACE = None
CAPTURE_FILTER = "ip"

# GeoIP databases
GEOIP_COUNTRY_DB = r"databases\GeoLite2-Country_20260120\GeoLite2-Country.mmdb"
GEOIP_ASN_DB = r"databases\GeoLite2-ASN_20260123\GeoLite2-ASN.mmdb"

# ML model
ML_MODEL_FILE = "decision_tree_model.pkl"

# Detection windows / thresholds
RATE_WINDOW = 10
RATE_THRESHOLD = 3000
SYN_THRESHOLD = 200
PORTSCAN_PORTS = 100
ALERT_COOLDOWN = 30

# Queue
INITIAL_QUEUE = 5000
MAX_QUEUE = 50000

# ============================================================
# GLOBALS
# ============================================================

packet_queue = queue.Queue(maxsize=INITIAL_QUEUE)
queue_lock = threading.Lock()
dynamic_queue_max = INITIAL_QUEUE

dns_cache = {}

packet_rate = defaultdict(deque)
syn_counter = defaultdict(deque)
port_counter = defaultdict(set)

alert_last_fired = {}

# Seen sets (one-time prints)
seen_countries = set()
seen_services = set()

# Load ML model
clf = joblib.load(ML_MODEL_FILE)

# GeoIP readers
geo_country = geoip2.database.Reader(GEOIP_COUNTRY_DB)
geo_asn = geoip2.database.Reader(GEOIP_ASN_DB)

# ============================================================
# CSV LOGGING
# ============================================================

packet_csv = open(CSV_FILE, "a", newline="")
packet_writer = csv.writer(packet_csv)

alert_csv = open(ALERT_FILE, "a", newline="")
alert_writer = csv.writer(alert_csv)

# ============================================================
# HELPERS
# ============================================================

def now():
    return time.time()

def is_private_ip(ip):
    return ip.startswith(("10.", "172.16.", "192.168."))

def alert(src_ip, alert_type, value):
    key = (src_ip, alert_type)
    last = alert_last_fired.get(key, 0)

    if now() - last < ALERT_COOLDOWN:
        return

    alert_last_fired[key] = now()
    ts = datetime.now().isoformat()
    print(f"[ALERT] {ts} {src_ip} {alert_type} {value}")
    alert_writer.writerow([ts, src_ip, alert_type, value])

def resolve_dns(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except:
        dns_cache[ip] = ip
    return dns_cache[ip]

# ============================================================
# GEOIP
# ============================================================

def geoip_lookup(ip):
    if is_private_ip(ip):
        return "PRIVATE", 0

    try:
        country = geo_country.country(ip)
        code = country.country.iso_code or "UNK"
    except:
        code = "UNK"

    try:
        asn = geo_asn.asn(ip).autonomous_system_number or 0
    except:
        asn = 0

    if code not in seen_countries:
        seen_countries.add(code)
        print(f"[INFO] New country detected: {code} ({asn})")

    return code, asn

# ============================================================
# SERVICE / APP INFERENCE
# ============================================================

def infer_service(packet):
    service = "UNKNOWN"

    if DNS in packet:
        service = "DNS"
    elif TCP in packet:
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            service = "HTTPS"
    elif UDP in packet:
        if packet[UDP].dport == 443 or packet[UDP].sport == 443:
            service = "QUIC_FLOW"

    if service not in seen_services:
        seen_services.add(service)
        print(f"[INFO] New service detected: {service}")

    return service

# ============================================================
# RULE-BASED SECURITY ANALYSIS
# ============================================================

def analyze_rules(packet, src_ip, dst_port):
    if is_private_ip(src_ip):
        return

    t = now()

    # Packet rate
    pr = packet_rate[src_ip]
    pr.append(t)
    while pr and t - pr[0] > RATE_WINDOW:
        pr.popleft()

    if len(pr) > RATE_THRESHOLD:
        alert(src_ip, "HIGH_PACKET_RATE", len(pr))

    # TCP analysis
    if TCP in packet:
        flags = packet[TCP].flags

        if flags & 0x02:  # SYN
            sc = syn_counter[src_ip]
            sc.append(t)
            while sc and t - sc[0] > RATE_WINDOW:
                sc.popleft()

            if len(sc) > SYN_THRESHOLD:
                alert(src_ip, "SYN_FLOOD", len(sc))

            pc = port_counter[src_ip]
            pc.add(dst_port)

            if len(pc) > PORTSCAN_PORTS:
                alert(src_ip, "PORT_SCAN", len(pc))

# ============================================================
# ML FEATURE EXTRACTION
# ============================================================

def extract_ml_features(packet):
    features = {
        "protocol": 0,
        "src_port": 0,
        "dst_port": 0,
        "packet_len": len(packet),
        "tcp_flags": 0,
        "is_private_dst": 0,
        "is_multicast_dst": 0,
    }

    if IP in packet:
        dst_ip = packet[IP].dst
        features["is_private_dst"] = int(is_private_ip(dst_ip))
        features["is_multicast_dst"] = int(
            dst_ip.startswith("239.") or dst_ip == "255.255.255.255"
        )

    if TCP in packet:
        features["protocol"] = 6
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["tcp_flags"] = int(packet[TCP].flags)
    elif UDP in packet:
        features["protocol"] = 17
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        features["protocol"] = 1

    return features

# ============================================================
# PACKET WORKER
# ============================================================

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

        dst_port = 0
        if TCP in packet:
            dst_port = packet[TCP].dport
        elif UDP in packet:
            dst_port = packet[UDP].dport

        # DNS cache
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore")

        resolve_dns(dst_ip)

        # Rule-based IDS
        analyze_rules(packet, src_ip, dst_port)

        # GeoIP + service
        country, asn = geoip_lookup(src_ip)
        service = infer_service(packet)

        # ML inference
        features = extract_ml_features(packet)
        df_feat = pd.DataFrame([features])
        ml_suspicious = int(clf.predict(df_feat)[0])

        # CSV write
        packet_writer.writerow([
            ts,
            features["protocol"],
            src_ip,
            dst_ip,
            features["src_port"],
            features["dst_port"],
            features["packet_len"],
            features["tcp_flags"],
            features["is_private_dst"],
            features["is_multicast_dst"],
            ml_suspicious,
            country,
            asn,
            service
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

# ============================================================
# SNIFF LOOP
# ============================================================

def enqueue_packet(packet):
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass

print("\nIDS sniffer running")
print(f"Packets → {CSV_FILE}")
print(f"Alerts  → {ALERT_FILE}")

print("\n=== Country / Private Legend ===")
print("PRIVATE -> local/private IPs")
print("UNK -> unknown public IP")
print("ISO2 -> country code (SE=Sweden, US=United States)")

print("\n=== Service Legend ===")
print("UNKNOWN -> not identified")
print("HTTPS / DNS / QUIC_FLOW -> inferred services\n")

worker = threading.Thread(target=packet_worker, daemon=True)
worker.start()

try:
    sniff(iface=INTERFACE, filter=CAPTURE_FILTER, prn=enqueue_packet, store=False)
except KeyboardInterrupt:
    packet_queue.put(None)
    worker.join()
    packet_csv.close()
    alert_csv.close()
    geo_country.close()
    geo_asn.close()
