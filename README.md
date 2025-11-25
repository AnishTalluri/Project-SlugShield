# Project-SlugShield
> Our "Edge AI Intrusion Detector" is a lightweight, on-device IDS that simulates edge monitoring in software. It watches local IoT and smart-device traffic and uses ML to spot unusual ports, data bursts, or odd packet patterns. Everything runs offline for privacy, with encrypted alerts, hashed logs, and a live web dashboard.

---

## Overview
Edge AI Intrusion Detector is a privacy-first, local intrusion detection system that analyzes simulated edge traffic (IoT and smart devices) using machine learning–based anomaly detection. It runs entirely on one computer (no cloud) and sends encrypted alerts and hashed summaries to a central dashboard—never raw packet data.

---

## Key Features
- Real-time anomaly detection using lightweight edge AI

- Privacy-first local inference (no cloud transmission)

- Adaptive learning that refines thresholds over time

- Web-based dashboard for live monitoring and alerts

- Encrypted/hashed log summaries for secure remote access

- Simulated edge traffic (IoT/smart devices) for repeatable testing

---

## Project Outline
- Vision: Lightweight, privacy-preserving local network anomaly detector with a FastAPI backend and React dashboard.

- Capture: Local traffic capture (software-simulated devices) using Python (e.g., libpcap/pcapy/scapy).

- Detection: Rule-based + ML anomaly detection for unusual ports, high data bursts, irregular packet patterns.

- Backend: FastAPI with REST + WebSocket for live alerts; SQLite for minimal, persistent storage.

- Dashboard: React UI showing live alerts, charts, and summaries over WebSockets.

- Privacy: No raw identifiers stored; daily hashing/rotation for metadata; summaries only.

- Team & Roles (4): Capture, Detection, Backend, Frontend.

- Sprints (Oct–Dec 2025): Incremental milestones for capture, detection, endpoints, UI, integration, polish.

---

## Detection Modules

### ARP Spoofing Detector
Detects Man-in-the-Middle (MITM) attacks through ARP spoofing by monitoring IP-to-MAC address mappings.

**How it Works:**
- Tracks all MAC addresses associated with each IP address on the network
- Uses a sliding time window to monitor recent MAC address changes
- Triggers alerts when the same IP is associated with multiple different MAC addresses within the threshold

**Attack Detection:**
In a normal network, one IP address maps to one consistent MAC address. During an ARP spoofing attack, an attacker sends fake ARP replies claiming their MAC address belongs to a legitimate IP (like a router). This detector identifies this behavior by:
1. Recording all IP-to-MAC mappings from ARP packets
2. Detecting when an IP suddenly has multiple different MAC addresses
3. Counting MAC changes within a configurable time window
4. Alerting when changes exceed the threshold (default: 3 changes in 10 seconds)

**Configuration** (`config.yaml`):
```yaml
window_seconds: 10                    # Time window for counting MAC changes
arp_mac_change_threshold: 3           # Number of MAC changes to trigger alert
```

**Files:**
- `ids_backend/arp_detector.py` - Main detector implementation
- `tools/simulate_arp_spoof.py` - Attack simulation tool for testing
- `test_arp_detector.py` - Live packet capture test runner
- `test_arp_unit.py` - Unit tests for detector logic

**Testing:**
```bash
# Run unit tests
python test_arp_unit.py

# Run live detection (Terminal 1)
sudo python test_arp_detector.py

# Simulate attack (Terminal 2)
sudo python tools/simulate_arp_spoof.py
```

**Alert Example:**
```
ARP spoofing detected! IP 192.168.1.100 has been associated with 3 different 
MAC addresses in 10 seconds. Current MAC: c3:03:14:5b:24:b0, 
All MACs seen: ['c3:03:14:5b:24:b0', '02:25:81:24:94:0a', 'ea:0f:b2:22:9c:38', 'a4:64:05:35:61:fb']
```

---

