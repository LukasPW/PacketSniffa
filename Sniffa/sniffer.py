"""
sniffer.py — packet capture, rule-based IDS, GeoIP enrichment, CSV logging.

Entry point has moved to ui.py. Start the sniffer from there via sniffer.start().
This module writes live counters into stats.py so the UI can read them.
"""
import os
import threading
import queue
import time
import csv
import socket
from datetime import datetime
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS,conf
import geoip2.database
import stats

# ML imports -- uncomment when model is ready
# import pandas as pd
# import joblib

# ============================================================
# CONFIG
# ============================================================

CSV_FILE       = "packet_log.csv"
ALERT_FILE     = "alerts.csv"
INTERFACE      = "wlan0"#conf.iface         # None = scapy picks the default interface
CAPTURE_FILTER = "ip"
log_Private = True

# GeoIP databases
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_COUNTRY_DB = os.path.join(BASE_DIR, "../databases/GeoLite2-Country_20260120/GeoLite2-Country.mmdb")
GEOIP_ASN_DB     = os.path.join(BASE_DIR, "../databases/GeoLite2-ASN_20260123/GeoLite2-ASN.mmdb")

# ML model -- uncomment when ready
# ML_MODEL_FILE = r"Sniffa\decision_tree_model.pkl"

# Detection windows / thresholds
RATE_WINDOW    = 10      # seconds
RATE_THRESHOLD = 3000    # packets / window  →  HIGH_PACKET_RATE
SYN_THRESHOLD  = 200     # SYNs   / window  →  SYN_FLOOD
PORTSCAN_PORTS = 100     # unique dst ports / window  →  PORT_SCAN
ALERT_COOLDOWN = 30      # seconds between repeat alerts for same (ip, type)

# Queue
PACKET_QUEUE_MAX = 50_000

# DNS
DNS_CACHE_LIMIT = 10_000   # stop reverse lookups after this many unique IPs

TRUSTED_ASNS = {
    3301,   # Telia
    1257,   # Tele2
    13335,  # Cloudflare
    16509,  # AWS
}

ASN_SERVICE_MAP = {
    # Swedish ISPs
    3301:  "TELIA_ISP",
    1257:  "TELE2_ISP",
    2119:  "TELENOR_ISP",
    # Global infra
    13335: "CLOUDFLARE",
    16509: "AWS",
    15169: "GOOGLE",
    8075:  "MICROSOFT",
    32934: "FACEBOOK_META",
    2906:  "NETFLIX",
    # CDNs
    54113: "FASTLY",
    20940: "AKAMAI",
}
KNOWN_HOSTS = {
    "192.168.1.1": "HOME_ROUTER",
}

# ============================================================
# MODULE-LEVEL STATE
# ============================================================

country_num_map = {}    # kept for ML re-enable

packet_queue = queue.Queue(maxsize=PACKET_QUEUE_MAX)

dns_cache   = {}
geoip_cache = {}

packet_rate  = defaultdict(deque)    # { src_ip: deque([ts, ...]) }
syn_counter  = defaultdict(deque)    # { src_ip: deque([ts, ...]) }
port_counter = defaultdict(deque)    # { src_ip: deque([(port, ts), ...]) }

alert_last_fired: dict[tuple, float] = {}

seen_countries: set[str] = set()
seen_services:  set[str] = set()

# ============================================================
# ML MODEL -- uncomment when training is ready
# ============================================================

# _raw_model = joblib.load(ML_MODEL_FILE)
# if isinstance(_raw_model, dict):
#     if "model" not in _raw_model:
#         raise RuntimeError("ML model file missing key 'model'")
#     clf = _raw_model["model"]
# else:
#     clf = _raw_model
# if not hasattr(clf, "predict"):
#     raise RuntimeError("Loaded ML object has no predict() method")
# stats.ml_enabled = True

# ============================================================
# GEOIP READERS  (opened lazily in start() so import is safe)
# ============================================================

geo_country = None
geo_asn     = None

# ============================================================
# CSV WRITERS   (opened in start())
# ============================================================

packet_csv    = None
packet_writer = None
alert_csv     = None
alert_writer  = None

# ============================================================
# HELPERS
# ============================================================

def _now() -> float:
    return time.time()

def is_private_ip(ip: str) -> bool:
    return ip.startswith(("10.", "172.16.", "192.168.", "127."))

def resolve_dns(ip: str) -> str:
    if ip in dns_cache:
        return dns_cache[ip]
    if len(dns_cache) >= DNS_CACHE_LIMIT:
        return ip
    try:
        dns_cache[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        dns_cache[ip] = ip
    return dns_cache[ip]

# ============================================================
# ALERTS
# ============================================================

def _alert(src_ip: str, alert_type: str, value: int,
           service: str = None, org: str = None) -> None:
    key = (src_ip, alert_type)
    if _now() - alert_last_fired.get(key, 0) < ALERT_COOLDOWN:
        return

    alert_last_fired[key] = _now()
    ts = datetime.now().isoformat()

    # Write to CSV and flush immediately so alerts survive crashes
    alert_writer.writerow([ts, src_ip, alert_type, value, org, service])
    alert_csv.flush()

    # Push into shared stats so the UI can display it
    stats.record_alert(ts, src_ip, alert_type, value, org, service)

# ============================================================
# GEOIP LOOKUP
# ============================================================

def _geoip_lookup(ip: str) -> tuple[str, int, str]:
    if ip in geoip_cache:
        return geoip_cache[ip]

    if is_private_ip(ip):
        geoip_cache[ip] = ("PRIVATE", 0, "PRIVATE")
        return geoip_cache[ip]

    try:
        country_code = geo_country.country(ip).country.iso_code or "UNK"
    except Exception:
        country_code = "UNK"

    try:
        asn_resp = geo_asn.asn(ip)
        asn      = asn_resp.autonomous_system_number or 0
        org      = asn_resp.autonomous_system_organization or "UNKNOWN_ORG"
    except Exception:
        asn = 0
        org = "UNKNOWN_ORG"

    if country_code not in seen_countries:
        seen_countries.add(country_code)

    result = (country_code, asn, org)
    geoip_cache[ip] = result
    return result

# ============================================================
# SERVICE INFERENCE
# ============================================================

def _infer_service(packet, asn: int) -> str:
    service = ASN_SERVICE_MAP.get(asn, "UNKNOWN")

    if DNS in packet:
        service += "_DNS"
    elif TCP in packet and (
        packet[TCP].dport in (443, 8443) or packet[TCP].sport in (443, 8443)
    ):
        service += "_HTTPS"
    elif UDP in packet and (
        packet[UDP].dport == 443 or packet[UDP].sport == 443
    ):
        service += "_QUIC"

    if service not in seen_services:
        seen_services.add(service)

    return service

# ============================================================
# RULE-BASED IDS
# ============================================================

def _analyze_rules(packet, src_ip: str, dst_port: int,
                   src_asn: int, org: str = None, service: str = None) -> None:
    if is_private_ip(src_ip) and not log_Private:
        return

    t = _now()
  
    # Packet rate
    pr = packet_rate[src_ip]
    pr.append(t)
    while pr and t - pr[0] > RATE_WINDOW:
        pr.popleft()
    if len(pr) > RATE_THRESHOLD:
        _alert(src_ip, "HIGH_PACKET_RATE", len(pr), service=service, org=org)
    if TCP in packet:
        flags = packet[TCP].flags
        
        # SYN flood
        if flags & 0x02:
            sc = syn_counter[src_ip]
            sc.append(t)
            while sc and t - sc[0] > RATE_WINDOW:
                sc.popleft()
  
            if len(sc) > SYN_THRESHOLD:
                _alert(src_ip, "SYN_FLOOD", len(sc), service=service, org=org)
  
    # Port scan (time-windowed)
    pc = port_counter[src_ip]
    pc.append((dst_port, t))
    while pc and t - pc[0][1] > RATE_WINDOW:
        pc.popleft()
    unique_ports = len({e[0] for e in pc})
    if unique_ports > PORTSCAN_PORTS:
        _alert(src_ip, "PORT_SCAN", unique_ports, service=service, org=org)


# ============================================================
# ML FEATURES -- uncomment when model is ready
# ============================================================

# def _extract_ml_features(packet, src_ip, country_code, asn):
#     if country_code not in country_num_map:
#         country_num_map[country_code] = len(country_num_map) + 1
#     features = {
#         "protocol_name_num": 0,
#         "src_asn":           int(asn),
#         "src_country_num":   country_num_map[country_code],
#         "protocol":          0,
#         "src_port":          0,
#         "dst_port":          0,
#         "packet_len":        len(packet),
#         "tcp_flags":         0,
#         "is_private_dst":    0,
#         "is_multicast_dst":  0,
#     }
#     if IP in packet:
#         dst_ip = packet[IP].dst
#         features["is_private_dst"]   = int(is_private_ip(dst_ip))
#         features["is_multicast_dst"] = int(
#             dst_ip.startswith("239.") or dst_ip == "255.255.255.255"
#         )
#     if TCP in packet:
#         features.update(protocol=6, protocol_name_num=6,
#                         src_port=packet[TCP].sport, dst_port=packet[TCP].dport,
#                         tcp_flags=int(packet[TCP].flags))
#     elif UDP in packet:
#         features.update(protocol=17, protocol_name_num=17,
#                         src_port=packet[UDP].sport, dst_port=packet[UDP].dport)
#     elif ICMP in packet:
#         features.update(protocol=1, protocol_name_num=1)
#     return features

# ============================================================
# PACKET WORKER
# ============================================================

def _packet_worker() -> None:
    while True:
        packet = packet_queue.get()
        if packet is None:
            break

        if IP not in packet:
            packet_queue.task_done()
            continue

        ts     = datetime.now().isoformat()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        src_port = dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        proto = (6  if TCP  in packet else
                 17 if UDP  in packet else
                 1  if ICMP in packet else 0)

        tcp_flags = int(packet[TCP].flags) if TCP in packet else 0
        pkt_len   = len(packet)

        # Passive DNS from passing responses
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if ans.type == 1:
                    dns_cache[ans.rdata] = ans.rrname.decode(errors="ignore")

        resolve_dns(dst_ip)

        country, asn, org = _geoip_lookup(src_ip)
        service           = _infer_service(packet, asn)

        _analyze_rules(packet, src_ip, dst_port, asn, org=org, service=service)

        is_private_dst   = int(is_private_ip(dst_ip))
        is_multicast_dst = int(
            dst_ip.startswith("239.") or dst_ip == "255.255.255.255"
        )

        # ML prediction -- uncomment when model is ready
        # features      = _extract_ml_features(packet, src_ip, country, asn)
        # df_feat       = pd.DataFrame([features])
        # df_feat       = df_feat.reindex(columns=clf.feature_names_in_, fill_value=0)
        # ml_suspicious = int(clf.predict(df_feat)[0])
        ml_suspicious = -1    # -1 = ML disabled

        packet_writer.writerow([
            ts, proto, src_ip, dst_ip,
            src_port, dst_port, pkt_len, tcp_flags,
            is_private_dst, is_multicast_dst,
            ml_suspicious, country, asn, org, service,
        ])

        # Update shared stats for the UI
        stats.record_packet(src_ip, proto, country, service)
        stats.queue_depth = packet_queue.qsize()

        stats.record_log(ts, src_ip, dst_ip, proto,
                 src_port, dst_port, country, service, pkt_len)

        packet_queue.task_done()

# ============================================================
# PACKET ENQUEUE  (called from scapy's sniff thread)
# ============================================================

def _enqueue_packet(packet) -> None:
    try:
        packet_queue.put_nowait(packet)
    except queue.Full:
        stats.dropped_packets += 1

# ============================================================
# PUBLIC API
# ============================================================

def start() -> None:
    """
    Open resources and begin capture. Blocks until KeyboardInterrupt.
    Called by ui.py in a background thread so the UI can run in the main thread.
    """
    global geo_country, geo_asn
    global packet_csv, packet_writer, alert_csv, alert_writer

    # Tell stats the queue ceiling so the UI can show a fill %
    stats.queue_max = PACKET_QUEUE_MAX

    geo_country = geoip2.database.Reader(GEOIP_COUNTRY_DB)
    geo_asn     = geoip2.database.Reader(GEOIP_ASN_DB)

    packet_csv    = open(CSV_FILE,  "a", newline="")
    packet_writer = csv.writer(packet_csv)
    alert_csv     = open(ALERT_FILE, "a", newline="")
    alert_writer  = csv.writer(alert_csv)

    worker = threading.Thread(target=_packet_worker, daemon=True)
    worker.start()

    try:
        sniff(iface=INTERFACE, filter=CAPTURE_FILTER,
              prn=_enqueue_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        packet_queue.put(None)
        worker.join()
        packet_csv.close()
        alert_csv.close()
        geo_country.close()
        geo_asn.close()
