#!/usr/bin/env python3
"""
Simplified Port Scan Detector test that doesn't use alerting.
"""

import threading
import time
import sys
import os

from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.port_scan_detector import port_scan_detector


class SimpleAlertManager:
    """Minimal alert manager that just prints alerts."""
    def push_alert(self, alert):
        print("\n" + "="*60)
        print(f"[ALERT] {alert['message']}")
        print(f"  Source: {alert['src']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Fast: ports={alert['fast_metrics']['unique_ports']}, hosts={alert['fast_metrics']['unique_hosts']}, syns={alert['fast_metrics']['syn']}")
        print("="*60 + "\n")


def main():
    print("=" * 60)
    print("Port Scan Detector - Simplified Test Mode")
    print("=" * 60)

    # Show where we're running from
    print(f"[TEST] CWD: {os.getcwd()}")
    print(f"[TEST] Python: {sys.executable}")

    # Load config
    app_config = load_config_file()
    print("\nConfiguration loaded:")
    print(f"  - Interface: {getattr(app_config, 'interface', 'N/A')}")
    print(f"  - Fast window: {getattr(app_config, 'portscan_fast_window_seconds', 'N/A')} seconds")
    print(f"  - Min unique ports (fast): {getattr(app_config, 'portscan_min_unique_ports_fast', 'N/A')}")
    print(f"  - Min SYNs (fast): {getattr(app_config, 'portscan_min_syns_fast', 'N/A')}")
    print(f"  - SYN/SYN-ACK ratio threshold: {getattr(app_config, 'portscan_max_syn_to_synack', 'N/A')}")

    # Build alert manager + detector
    alert_mngr = SimpleAlertManager()
    detector = port_scan_detector(app_config, alert_mngr)

    # Build packet capture
    sniffer = PacketCapture(app_config)
    print(f"\n[TEST] PacketCapture.interface = {sniffer.interface!r}")

    # Register detector callback
    sniffer.add_detection(detector.analyze_packet)

    # Start sniffing in a background thread
    thread = threading.Thread(target=sniffer.start_sniff, daemon=True)
    print("[TEST] Starting sniffing thread...")
    thread.start()
    time.sleep(0.5)  # Give thread time to start

    print("\n✓ Port scan detector is running.")
    print("Run nmap in another terminal:")
    print("  sudo nmap -sS -p 1-200 127.0.0.1\n")
    print("Watching traffic... Press Ctrl+C to stop.\n")

    try:
        heartbeat = 0
        while True:
            time.sleep(1)
            heartbeat += 1
            if heartbeat % 5 == 0:
                print(f"[TEST] Heartbeat #{heartbeat} - still watching...")
    except KeyboardInterrupt:
        print("\nShutting down...")
        sniffer.stop_sniff()
        print("Stopped.")


if __name__ == '__main__':
    main()
