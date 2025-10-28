import threading 
import time 
from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.detectors.icmp_flood import icmp_counter_detector
from ids_backend.arp_detector import arp_spoof_detector
from ids_backend.ssh_detector import ssh_bruteforce_detector
from ids_backend.alerting import alert_manager

def main():
    print("=" * 60)
    print("SlugShield IDS - Starting Detection System")
    print("=" * 60)
    
    # Load configuration
    app_config = load_config_file()
    print("\nConfiguration loaded:")
    print(f"  - Time window: {app_config.window_seconds} seconds")
    print(f"  - ICMP threshold: {app_config.icmp_threshold_per_window} packets")
    print(f"  - ARP threshold: {app_config.arp_mac_change_threshold} MAC changes")
    print(f"  - SSH threshold: {app_config.ssh_threshold_per_window} attempts")
    
    # Initialize alert manager
    alert_mngr = alert_manager(app_config)
    
    # Initialize all detectors
    icmp_detector = icmp_counter_detector(app_config, alert_mngr)
    arp_detector = arp_spoof_detector(app_config, alert_mngr)
    ssh_detector = ssh_bruteforce_detector(app_config, alert_mngr)
    
    # Set up packet capture and register all detectors
    live_packet_sniffer = PacketCapture(app_config)
    live_packet_sniffer.add_detection(icmp_detector.analyze_packet)
    live_packet_sniffer.add_detection(arp_detector.analyze_packet)
    live_packet_sniffer.add_detection(ssh_detector.analyze_packet)
    
    print("\nActive Detectors:")
    print("  ✓ ICMP Flood Detector")
    print("  ✓ ARP Spoofing Detector")
    print("  ✓ SSH Brute Force Detector")
    
    # Start capture in background thread
    thread = threading.Thread(target=live_packet_sniffer.start_sniff, daemon=True)
    thread.start()

    print("\n✓ All detectors running!")
    print("\nPress Ctrl+C to stop...\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n\nShutting down...')
        live_packet_sniffer.stop_sniff()
        print("Stopped.\n")

if __name__ == '__main__':
    main()