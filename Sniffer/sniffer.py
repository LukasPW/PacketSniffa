import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from scapy.layers.tls.all import TLS, TLSClientHello
from datetime import datetime
import socket
import csv
import time
from collections import defaultdict, deque
from geoip2.database import Reader

# -----------------------------
# CONFIGURATION
# -----------------------------
CSV_FILE = "packet_log.csv"
ALERT_FILE = "alerts.csv"
INTERFACE = None
CAPTURE_FILTER = "ip"

# Detection windows
RATE_WINDOW = 10
PORTSCAN_WINDOW = 10
SHORT_CONN_WINDOW = 60

# Thresholds
RATE_THRESHOLD = 3000
SYN_THRESHOLD = 200
PORTSCAN_PORTS = 100
SHORT_CONN_THRESHOLD = 50
HALF_OPEN_RATIO_THRESHOLD = 2

# Alert cooldown
ALERT_COOLDOWN = 30

# Queue
INITIAL_QUEUE = 5000
MAX_QUEUE = 50000

# GeoIP database paths
GEOASN_DB = r"databases\GeoLite2-ASN_20260123\GeoLite2-ASN.mmdb"
GEOCOUNTRY_DB = r"databases\GeoLite2-Country_20260120\GeoLite2-Country.mmdb"

# Whitelist safe IPs / ASNs (like ISP backbones)
WHITELIST_IPS = {"81.227.188.63"}  # example Telia IP
WHITELIST_ASNS = {1299}             # Telia ASN

# -----------------------------
# GLOBALS
# -----------------------------
packet_queue = queue.Queue(maxsize=INITIAL_QUEUE)

# DNS caching
dns_cache = {}

# Tier-1
packet_rate = defaultdict(deque)
syn_counter = defaultdict(deque)
port_counter = defaultdict(set)
alert_last_fired = {}

# Tier-2
tcp_connections = {}
short_conn_history = defaultdict(deque)

# GeoIP caching
geoip_cache = {}

# Queue management
queue_lock = threading.Lock()
dynamic_queue_max = INITIAL_QUEUE

# -----------------------------
# CSV LOGGING
# -----------------------------
packet_csv = open(CSV_FILE, "w", newline="")
packet_writer = csv.writer(packet_csv)
packet_writer.writerow([
    "timestamp","protocol","src_ip","dst_ip","src_port","dst_port",
    "packet_len","tcp_flags","is_private_dst","is_multicast_dst",
    "suspicious","src_country","src_asn","src_sni"
])

alert_csv = open(ALERT_FILE, "w", newline="")
alert_writer = csv.writer(alert_csv)
alert_writer.writerow(["timestamp","src_ip","alert_type","value"])

# -----------------------------
# GEOIP READERS
# -----------------------------
geo_reader_asn = Reader(GEOASN_DB)
geo_reader_country = Reader(GEOCOUNTRY_DB)

# -----------------------------
# HELPERS
# -----------------------------
def now():
    return time.time()

def enrich_geoip(ip):
    """Return (country, ASN) tuple for source IP."""
    if ip in geoip_cache:
        return geoip_cache[ip]
    try:
        country = geo_reader_country.country(ip).country.iso_code
    except:
        country = "UNK"
    try:
        asn = geo_reader_asn.asn(ip).autonomous_system_number
    except:
        asn = 0
    geoip_cache[ip] = (country, asn)
    return country, asn

def resolve_dns(ip):
    if ip in dns_cache:
        return
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except:
        dns_cache[ip] = ip

def is_whitelisted(src_ip):
    """Return True if IP or ASN is whitelisted."""
    if src_ip in WHITELIST_IPS:
        return True
    _, asn = enrich_geoip(src_ip)
    if asn in WHITELIST_ASNS:
        return True
    return False

def alert(src_ip, alert_type, value):
    """Fire alert unless IP is whitelisted."""
    if is_whitelisted(src_ip):
        return False
    key = (src_ip, alert_type)
    last = alert_last_fired.get(key, 0)
    if now() - last < ALERT_COOLDOWN:
        return False
    alert_last_fired[key] = now()
    ts = datetime.now().isoformat()
    print(f"[ALERT] {ts} {src_ip} {alert_type} {value}")
    alert_writer.writerow([ts, src_ip, alert_type, value])
    return True

def extract_sni(packet):
    """Extract TLS SNI if present."""
    try:
        if TCP in packet and packet[TCP].dport == 443 and packet.haslayer(TLSClientHello):
            ext = packet[TLSClientHello].extensions
            if ext and ext[0].server_name:
                return ext[0].server_name.decode(errors="ignore")
    except:
        pass
    return ""

# -----------------------------
# ANALYSIS FUNCTION (Tier1 + Tier2)
# -----------------------------
def analyze(packet, src_ip, dst_ip, dst_port):
    # skip whitelisted/internal
    if src_ip.startswith(("10.", "172.16.", "192.168.")) or is_whitelisted(src_ip):
        return

    t = now()

    # Tier1: packet rate
    pr = packet_rate[src_ip]
    pr.append(t)
    while pr and t - pr[0] > RATE_WINDOW:
        pr.popleft()
    if len(pr) > RATE_THRESHOLD:
        alert(src_ip, "HIGH_PACKET_RATE", len(pr))

    # Tier1: SYN flood / port scan
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

    # Tier2: TCP lifecycle tracking
    if TCP in packet:
        key = (src_ip, dst_ip, dst_port)
        conn = tcp_connections.get(key, {"syn":0,"fin":0,"start_time":t,"state":"CLOSED","last_seen":t})
        flags = packet[TCP].flags

        # SYN -> start connection
        if flags & 0x02:
            conn["syn"] += 1
            conn["state"] = "SYN_SENT"
            conn["last_seen"] = t

        # FIN -> close connection
        if flags & 0x01:
            conn["fin"] += 1
            conn["state"] = "CLOSED"
            conn["last_seen"] = t
            duration = t - conn.get("start_time", t)
            short_conn_history[src_ip].append((t,duration))

        # RST -> abrupt close
        if flags & 0x04:
            conn["state"] = "CLOSED"
            conn["last_seen"] = t
            duration = t - conn.get("start_time", t)
            short_conn_history[src_ip].append((t,duration))

        tcp_connections[key] = conn

        # short-lived TCP alert
        sh = short_conn_history[src_ip]
        while sh and t - sh[0][0] > SHORT_CONN_WINDOW:
            sh.popleft()
        if len(sh) > SHORT_CONN_THRESHOLD:
            alert(src_ip, "SHORT_LIVED_TCP", len(sh))

        # half-open detection
        if conn["fin"] > 0:
            ratio = conn["syn"] / conn["fin"]
            if ratio >= HALF_OPEN_RATIO_THRESHOLD:
                alert(src_ip, "HALF_OPEN_TCP", ratio)
        short_conn_history[src_ip] = sh

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

        # DNS caching
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore")

        resolve_dns(dst_ip)

        # auto-labeling + analysis
        analyze(packet, src_ip, dst_ip, dst_port)
        suspicious = 0
        for (ip, alert_type), alert_ts in alert_last_fired.items():
            if ip == src_ip and now() - alert_ts < ALERT_COOLDOWN:
                suspicious = 1
                break

        is_private = int(dst_ip.startswith(("10.","172.16.","192.168.")))
        is_multicast = int(dst_ip.startswith("239.") or dst_ip == "255.255.255.255")

        src_country, src_asn = enrich_geoip(src_ip)
        src_sni = extract_sni(packet)

        packet_writer.writerow([
            ts, protocol, src_ip, dst_ip, src_port, dst_port,
            pkt_len, flags, is_private, is_multicast, suspicious,
            src_country, src_asn, src_sni
        ])

        packet_queue.task_done()

        # dynamic queue resizing
        with queue_lock:
            qsize = packet_queue.qsize()
            if qsize > dynamic_queue_max * 0.8:
                dynamic_queue_max = min(dynamic_queue_max * 2, MAX_QUEUE)
                packet_queue.maxsize = dynamic_queue_max
            elif qsize < dynamic_queue_max * 0.2:
                dynamic_queue_max = max(dynamic_queue_max // 2, INITIAL_QUEUE)
                packet_queue.maxsize = dynamic_queue_max

# -----------------------------
# PACKET ENQUEUE
# -----------------------------
def enqueue_packet(packet):
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        pass

# -----------------------------
# MAIN SNIFFER
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
