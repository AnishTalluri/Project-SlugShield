"""
Test runner for Port Scan Detection.

This script launches the live IDS backend with the port scan detector enabled.
To test it, run a port scan from another terminal or machine using a tool like:

    sudo nmap -sS -p 20-100 <your-local-IP>

Make sure you run this test script with sudo so it can access network interfaces.
"""

import threading
import time
import sys
import os

from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.port_scan_detector import port_scan_detector
from ids_backend.alerting import alert_broadcaster


def main():
    print("=" * 60)
    print("Port Scan Detector - Test Mode")
    print("=" * 60)

    # Show where we're running from (helps with config.yaml path issues)
    print(f"[TEST][DEBUG] CWD: {os.getcwd()}")
    print(f"[TEST][DEBUG] Python: {sys.executable}")

    # Load config
    app_config = load_config_file()
    print("\nConfiguration loaded:")
    print(f"  - Fast window: {getattr(app_config, 'portscan_fast_window_seconds', 'N/A')} seconds")
    print(f"  - Min unique ports (fast): {getattr(app_config, 'portscan_min_unique_ports_fast', 'N/A')}")
    print(f"  - SYN/SYN-ACK ratio threshold: {getattr(app_config, 'portscan_max_syn_to_synack', 'N/A')}")
    print(f"[TEST][DEBUG] app_config.interface = {getattr(app_config, 'interface', None)!r}")

    # Build alert manager + detector
    alert_mngr = alert_broadcaster()
    detector = port_scan_detector(app_config, alert_mngr)

    # Build packet capture and show which iface it will sniff
    sniffer = PacketCapture(app_config)
    print(f"[TEST][DEBUG] PacketCapture.interface = {sniffer.interface!r}")

    # Register detector callback
    sniffer.add_detection(detector.analyze_packet)

    # Start sniffing in a background thread
    thread = threading.Thread(target=sniffer.start_sniff, daemon=True)
    print("[TEST][DEBUG] Starting sniffing thread...")
    thread.start()

    print("\n✓ Port scan detector is running.")
    print("Use a port scan tool in another terminal to simulate scanning activity.")
    print("Example: sudo nmap -sS -p 20-100 <target-ip>\n")
    print("Watching traffic... Press Ctrl+C to stop.\n")

    try:
        heartbeat = 0
        while True:
            time.sleep(1)
            heartbeat += 1
            # heartbeat to know main loop is running
            if heartbeat % 5 == 0:
                print("[TEST][DEBUG] Main loop heartbeat: still watching traffic...")
    except KeyboardInterrupt:
        print("\nShutting down...")
        sniffer.stop_sniff()
        print("Stopped.")


if __name__ == '__main__':
    main()

