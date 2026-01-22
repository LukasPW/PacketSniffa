# Network Packet Sniffer (Educational & Diagnostic)

## Overview

This project is a **Python-based network packet sniffer** designed for:

- Network diagnostics
- Educational exploration of TCP/IP, UDP, ICMP, and QUIC
- Passive security observation

It **only inspects metadata**, not packet contents, ensuring ethical usage.

---

## Features

1. **Session-based logging**
   - Logs reset each run
   - Saves to text (`packet_log.txt`) and CSV (`packet_log.csv`)
2. **Protocol detection**
   - TCP, UDP, ICMP, QUIC (likely)
3. **Destination labeling**
   - Multicast, Broadcast, Private LAN
   - DNS hostname resolution when available
4. **Security monitoring**
   - High traffic rate detection
   - SYN-heavy scan-like behavior
   - Short-lived connection churn detection
5. **Per-host traffic visualization**
   - Simple text-based bar graph
6. **CSV export**
   - Easy to analyze with Excel, Google Sheets, etc.

---

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- **Npcap** (for Windows) or equivalent packet capture library for your system

Install Scapy via pip:

```bash
pip install scapy
```

> **Note:** On Windows, make sure to install Npcap to allow Scapy to capture packets. Choose the default installation options and enable "WinPcap Compatible Mode" if prompted.  
> On Linux/macOS, ensure you have `libpcap` installed (usually included by default) and run the sniffer with root privileges.

## Running the Sniffer

- Open a terminal with administrator/root privileges
- Navigate to the project folder
- Run the sniffer:

```bash
python sniffer.py
```

## Observe live logs in the terminal

Logs are saved in:

- `packet_log.txt` (text log)
- `packet_log.csv` (CSV log)

Press `CTRL+C` to stop and see the summary, including:

- Total packets per protocol
- Top hosts
- Security observations

---

## Security & Privacy Notes

- The sniffer does not inspect payloads (no URL paths, message contents, or user data)
- Only uses metadata for:
  - Traffic statistics
  - Security anomaly detection
- Multicast, broadcast, and private LAN traffic is labeled rather than removed
- QUIC traffic is labeled “QUIC (likely)” since headers are encrypted
- Designed for local/test networks only, not public networks

---

## Git Ignore Instructions

To prevent log files from being committed:

1. Create or edit a `.gitignore` file in your repository root
2. Add the following lines:

- `packet_log.txt`
- `packet_log.csv`

3. If these files were already tracked, remove them from Git:

```bash
git rm --cached packet_log.txt packet_log.csv
git commit -m "Stop tracking log files"
```

After this, Git will ignore them automatically.

---

## Learning Goals

- Understand network protocols (TCP, UDP, ICMP, QUIC)
- Observe and visualize traffic per host
- Identify simple anomalous behaviors (rate spikes, SYN-heavy patterns, short-lived connections)
- Explore DNS resolution and local network traffic labeling

---

## Disclaimer

This tool is intended strictly for educational and diagnostic use on networks you own or are authorized to test. Unauthorized sniffing on public or private networks may be illegal.
