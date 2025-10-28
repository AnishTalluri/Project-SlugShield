"""
SSH Brute Force Detector - Live Test

This test runner monitors for SSH brute force attempts on the network.
To test it, you can either:
1. Monitor real SSH traffic on your network
2. Use nmap to scan port 22 on an external target

Usage:
    sudo python3 test_ssh_live.py
"""

import threading 
import time 
from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.ssh_detector import ssh_bruteforce_detector
from ids_backend.alerting import alert_manager

def main():
    print("=" * 60)
    print("SSH Brute Force Detector - Live Test Mode")
    print("=" * 60)
    
    # Load configuration
    app_config = load_config_file()
    print(f"\nConfiguration loaded:")
    print(f"  - Time window: {app_config.window_seconds} seconds")
    print(f"  - SSH threshold: {app_config.ssh_threshold_per_window} attempts")
    
    # Set up alert manager and detector
    alert_mngr = alert_manager(app_config)
    ssh_detector = ssh_bruteforce_detector(app_config, alert_mngr)
    
    # Set up packet capture
    live_packet_sniffer = PacketCapture(app_config)
    live_packet_sniffer.add_detection(ssh_detector.analyze_packet)
    
    # Start capture in background thread with TCP filter
    class TCPCapture:
        def __init__(self, app_config):
            self.interface = app_config.interface
            self.store_detectors = []
            self.running = False
        
        def add_detection(self, detector):
            self.store_detectors.append(detector)
        
        def process_packet(self, packet):
            for detector in self.store_detectors:
                try:
                    detector(packet)
                except Exception as e:
                    print(f'Error: {e}')
        
        def start_sniff(self):
            from scapy.all import sniff
            self.running = True
            # Only capture TCP packets to port 22
            sniff(filter='tcp and port 22', prn=self.process_packet, store=False, iface=self.interface)
    
    tcp_sniffer = TCPCapture(app_config)
    tcp_sniffer.add_detection(ssh_detector.analyze_packet)
    
    thread = threading.Thread(target=tcp_sniffer.start_sniff, daemon=True)
    thread.start()

    print("\n✓ SSH brute force detector is running!")
    print("\nTo test, in another terminal run:")
    print("  # Scan an external IP (replace with a real target you own/have permission to scan)")
    print("  nmap -p 22 --max-retries 0 --host-timeout 1s <target-ip>")
    print("\n  Or repeatedly try to connect to a real SSH server:")
    print("  for i in {1..15}; do nc -zv <ssh-server-ip> 22 2>&1; sleep 0.5; done")
    print("\nWatching for SSH traffic on port 22... (Ctrl+C to stop)\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n\nShutting down...')
        print("Stopped.\n")

if __name__ == '__main__':
    main()
