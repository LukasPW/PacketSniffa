# 🛡️ Network Packet Sniffer & IDS (Python)

![Python Version](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🌐 Overview

This project is a **Python-based network packet sniffer and lightweight IDS** for:

- Network diagnostics
- Security anomaly detection
- Educational exploration of TCP/IP, UDP, ICMP, and QUIC traffic

It **only inspects metadata**, not packet payloads, so it’s ethical for testing on networks you own or are authorized to monitor.

---

## ⚠️ Disclaimer

## Intended for educational and diagnostic use **only** on networks you own or are authorized to test. Unauthorized sniffing is illegal.

---

## ⚡ Features

| Feature                        | Description                                                      |
| ------------------------------ | ---------------------------------------------------------------- |
| **Packet Logging**             | Logs metadata to CSV (`packet_log.csv`) & alerts to `alerts.csv` |
| **Protocol Detection**         | TCP, UDP, ICMP, DNS, HTTPS, QUIC (inferred)                      |
| **Destination Labeling**       | Private, multicast, broadcast IPs; DNS resolution caching        |
| **GeoIP & ASN Mapping**        | Maps IPs to country codes and organizations                      |
| **Service Inference**          | Infers service type from protocol/port (e.g., Cloudflare, AWS)   |
| **Rule-Based IDS**             | Detects high packet rate, SYN floods, port scans                 |
| **ML-Based Anomaly Detection** | Uses decision tree model to flag suspicious hosts                |
| **Dynamic Queue Handling**     | Auto-adjusts capture queue to prevent packet loss                |
| **CSV Export**                 | Ready for Excel, Google Sheets, or analysis                      |

---

## 🛠️ Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- [GeoIP2](https://pypi.org/project/geoip2/)
- [pandas](https://pandas.pydata.org/)
- [joblib](https://joblib.readthedocs.io/)
- GeoLite2 databases: **Country** & **ASN**
- **Npcap** (Windows) or libpcap equivalent (Linux/macOS)

Install Python dependencies:

```bash
pip install scapy geoip2 pandas joblib scikit-learn
```

Note: On Windows, install Npcap. Enable "WinPcap Compatible Mode" if prompted.  
On Linux/macOS, ensure libpcap is installed and run as root.

---

## 🚀 Running the Sniffer/IDS

1. Open terminal as administrator/root
2. Navigate to project folder
3. Run:

```bash
python sniffer.py
```

Packets are processed in real-time. Logs and alerts are saved to:

- `packet_log.csv` – metadata + ML flags
- `alerts.csv` – triggered security alerts

Press `CTRL+C` to stop. Program closes files & threads safely.

---

## 🔎 Security & Privacy Notes

- No payload inspection (no URLs, messages, or user data)
- Metadata only: IPs, ports, protocols, packet length, TCP flags
- Labels private, multicast, and broadcast traffic
- Designed for **local/test networks only**

---

## 📝 Git Ignore Instructions

Add to `.gitignore` to avoid committing logs:

```
packet_log.csv
alerts.csv
```

If already tracked:

```bash
git rm --cached packet_log.csv alerts.csv
git commit -m "Ignore log files"
```

---

## 🎯 Learning Goals

- Understand network protocols (TCP, UDP, ICMP, QUIC)
- Explore DNS resolution, GeoIP, ASN mapping
- Detect anomalies via rule-based and ML methods
- Analyze traffic per host and per service

---

## ⚠️ IDS Thresholds & Rules

| Alert Type       | Condition / Threshold             | Notes                                |
| ---------------- | --------------------------------- | ------------------------------------ |
| High Packet Rate | > 3000 packets in 10 seconds      | Detects abnormal traffic spikes      |
| SYN Flood        | > 200 SYN packets in 10 seconds   | TCP flood detection                  |
| Port Scan        | > 100 unique destination ports    | Detects horizontal scanning          |
| Alert Cooldown   | 30 seconds between same alert     | Prevents alert spam                  |
| Queue Size       | Initial: 5000 packets, Max: 50000 | Dynamically adjusts based on traffic |
| Trusted ASNs     | 3301, 1257, 13335, 16509          | Alerts may ignore trusted networks   |

---

## 🛠️ Quick Legend

| Symbol / Label | Meaning                                    |
| -------------- | ------------------------------------------ |
| `PRIVATE`      | Local/private IP                           |
| `UNK`          | Unknown public IP                          |
| `ISO2`         | Country code (SE=Sweden, US=United States) |
| `UNKNOWN`      | Service not identified                     |
| `_DNS`         | DNS traffic inferred                       |
| `_HTTPS`       | HTTPS traffic inferred                     |
| `_QUIC`        | QUIC traffic inferred                      |
