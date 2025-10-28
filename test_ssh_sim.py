"""
SSH Brute Force Simulator - Unit Test

This script simulates SSH brute force attempts by creating fake TCP SYN packets
to port 22 from the same source IP.
"""

from scapy.all import IP, TCP
from ids_backend.ssh_detector import ssh_bruteforce_detector
from ids_backend.alerting import alert_manager

# Mock configuration for testing
class MockConfig:
    def __init__(self):
        self.window_seconds = 10
        self.ssh_threshold_per_window = 10
        self.logging = {
            'alerts_log': 'test_alerts.log',
            'level': 'INFO'
        }

print("=" * 60)
print("SSH Brute Force Detector - Unit Test")
print("=" * 60)

# Set up detector
config = MockConfig()
alert_mngr = alert_manager(config)
detector = ssh_bruteforce_detector(config, alert_mngr)

print(f"\nConfiguration:")
print(f"  - Window: {config.window_seconds} seconds")
print(f"  - Threshold: {config.ssh_threshold_per_window} attempts")

print("\nSimulating SSH brute force attack...")
print("Sending 12 SSH connection attempts from 192.168.1.55\n")

# Send more than threshold attempts
for i in range(12):
    pkt = IP(src="192.168.1.55")/TCP(dport=22, flags="S")
    detector.analyze_packet(pkt)
    print(f"  Attempt {i+1}: SYN to port 22 from 192.168.1.55")

print("\n" + "=" * 60)
print("Simulation done!")
print("=" * 60)
print("\nExpected: Alert triggered after 10th attempt")
print("Check 'test_alerts.log' for details.")

