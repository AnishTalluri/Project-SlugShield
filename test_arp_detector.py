"""
Test runner for ARP spoofing detection.

This script runs the IDS with the ARP detector enabled.

Run this (the detector) first --> then the simulate_arp_spoof.py script in another terminal to test it.


Anish's Note 1: If using WSL (Like Anish is) --> run this cmd in WSL with the venv activated in terminal 1:
-------------------------------------------------------------------------------------------------------------
    sudo .../Project-SlugShield/venv/bin/python test_arp_detector.py
-------------------------------------------------------------------------------------------------------------
It needs sudo to access network interfaces for packet capture.

Anish's Note 2: Once the above is running, open a new terminal --> activate the venv again and run:
-------------------------------------------------------------------------------------------------------------
    sudo .../Project-SlugShield/venv/bin/python tools/simulate_arp_spoof.py
-------------------------------------------------------------------------------------------------------------
This will simulate ARP spoofing packets to trigger the detector (should see an alert triggered on the third
different MAC for same IP. It will show up in terminal 1, where the detector is running).

"""

import threading 
import time
from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.arp_detector import arp_spoof_detector
from ids_backend.alerting import alert_manager

def main():
    print("=" * 60)
    print("ARP Spoofing Detector - Test Mode")
    print("=" * 60)
    
    # Load configuration
    app_config = load_config_file()
    print(f"\nConfiguration loaded:")
    print(f"  - Time window: {app_config.window_seconds} seconds")
    print(f"  - ARP threshold: {app_config.arp_mac_change_threshold} MAC changes")
    
    # Set up alert manager and detector
    alert_mngr = alert_manager(app_config)
    arp_detector = arp_spoof_detector(app_config, alert_mngr)
    
    # Set up packet capture
    live_packet_sniffer = PacketCapture(app_config)
    live_packet_sniffer.add_detection(arp_detector.analyze_packet)
    
    # Start capture in background thread
    thread = threading.Thread(target=live_packet_sniffer.start_sniff_arp, daemon=True)
    thread.start()

    print("\n✓ ARP spoofing detector is running!")
    print("\nTo test:")
    print("  1. Open another terminal")
    print("  2. Activate your venv")
    print("  3. Run: python tools/simulate_arp_spoof.py")
    print("\nWatching for ARP packets... (Ctrl+C to stop)\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n\nShutting down...')
        live_packet_sniffer.stop_sniff()
        print("Stopped.\n")

if __name__ == '__main__':
    main()
