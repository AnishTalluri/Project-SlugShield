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