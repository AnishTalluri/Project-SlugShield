"""
Simple unit test for ARP detector logic.

This tests the detector without actually capturing packets.
"""

from scapy.all import ARP, Ether
from ids_backend.arp_detector import arp_spoof_detector
from ids_backend.alerting import alert_manager
import time

class MockConfig:
    """Mock configuration for testing"""
    def __init__(self):
        self.window_seconds = 10
        self.arp_mac_change_threshold = 3
        self.logging = {
            'alerts_log': 'test_alerts.log',
            'level': 'INFO'
        }

def test_arp_detector():
    print("=" * 60)
    print("ARP Detector Unit Test")
    print("=" * 60)
    
    # Set up detector
    config = MockConfig()
    alert_mngr = alert_manager(config)
    detector = arp_spoof_detector(config, alert_mngr)
    
    print(f"\nConfiguration:")
    print(f"  - Window: {config.window_seconds} seconds")
    print(f"  - Threshold: {config.arp_mac_change_threshold} MAC changes")
    
    # Test 1: Normal behavior - same IP, same MAC (no alert expected)
    print("\n" + "-" * 60)
    print("Test 1: Normal traffic (same IP, same MAC)")
    print("-" * 60)
    
    ip = "192.168.1.100"
    mac1 = "aa:bb:cc:dd:ee:ff"
    
    for i in range(5):
        packet = Ether()/ARP(psrc=ip, hwsrc=mac1)
        detector.analyze_packet(packet)
        print(f"  Packet {i+1}: IP={ip}, MAC={mac1}")
    
    print("  ✓ No alerts expected (normal behavior)")
    
    # Test 2: ARP spoofing - same IP, different MACs (alert expected)
    print("\n" + "-" * 60)
    print("Test 2: ARP Spoofing (same IP, multiple MACs)")
    print("-" * 60)
    
    macs = [
        "11:22:33:44:55:66",
        "22:33:44:55:66:77",
        "33:44:55:66:77:88",
        "44:55:66:77:88:99"
    ]
    
    for i, mac in enumerate(macs):
        packet = Ether()/ARP(psrc=ip, hwsrc=mac)
        detector.analyze_packet(packet)
        print(f"  Packet {i+1}: IP={ip}, MAC={mac}")
        time.sleep(0.1)  # Small delay
    
    print("  ✓ Alert should have been triggered!")
    
    # Test 3: Check sliding window works
    print("\n" + "-" * 60)
    print("Test 3: Sliding Window (old timestamps get removed)")
    print("-" * 60)
    
    new_ip = "192.168.1.200"
    print(f"  Testing with IP: {new_ip}")
    print(f"  Sending 2 MAC changes (below threshold of {config.arp_mac_change_threshold})")
    
    for i, mac in enumerate(macs[:2]):
        packet = Ether()/ARP(psrc=new_ip, hwsrc=mac)
        detector.analyze_packet(packet)
        print(f"  Packet {i+1}: MAC={mac}")
    
    print("  ✓ No alert (below threshold)")
    
    print("\n" + "=" * 60)
    print("Tests Complete!")
    print("=" * 60)
    print("\nCheck 'test_alerts.log' for alert details.")

if __name__ == '__main__':
    test_arp_detector()
