import csv
import random
from datetime import datetime, timedelta

CSV_FILE = "packet_log.csv"
NUM_ROWS = 1000

ATTACK_TYPES = ["SYN_FLOOD", "PORT_SCAN", "UDP_FLOOD"]
COUNTRIES = [("US", 64500), ("RU", 64510), ("CN", 64520), ("BR", 64530)]
PRIVATE_TARGETS = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_row(ts, attack):
    src_ip = random_ip()
    dst_ip = random.choice(PRIVATE_TARGETS)
    country, asn = random.choice(COUNTRIES)

    if attack == "SYN_FLOOD":
        return [
            ts, 6, "TCP",
            src_ip, dst_ip,
            random.randint(40000, 60000), 80,
            60, 2, 0, 1, 203,
            country, asn, "", "HTTP_FLOOD"
        ]

    if attack == "PORT_SCAN":
        return [
            ts, 6, "TCP",
            src_ip, dst_ip,
            random.randint(40000, 60000), random.randint(20, 1024),
            60, 2, 0, 1, 22,
            country, asn, "", "PORT_SCAN"
        ]

    if attack == "UDP_FLOOD":
        return [
            ts, 17, "UDP",
            src_ip, dst_ip,
            random.randint(40000, 60000), random.randint(1000, 9000),
            1358, 0, 0, 1, 0,
            country, asn, "", "UDP_FLOOD"
        ]

start_time = datetime.now() - timedelta(minutes=5)

rows = []
for i in range(NUM_ROWS):
    ts = (start_time + timedelta(milliseconds=i * 2)).isoformat()
    attack = random.choice(ATTACK_TYPES)
    rows.append(generate_row(ts, attack))

with open(CSV_FILE, "a", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(rows)

print(f"[OK] Injected {NUM_ROWS} synthetic malicious rows into {CSV_FILE}")
