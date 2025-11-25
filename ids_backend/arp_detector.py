"""
ARP Spoofing Detector

This detector identifies potential ARP spoofing attacks (Man-in-the-Middle attacks).

How ARP Spoofing Works:
- An attacker sends fake ARP replies to a victim
- These fake replies say "Hey, I'm the router/server you want to talk to, send packets to MY MAC address"
- If successful, all traffic between victim and destination goes through the attacker
- The attacker can then sniff, modify, or drop the traffic

How We Detect It:
- We track the mapping between IP addresses and MAC addresses
- In a normal network, one IP address should consistently map to ONE MAC address
- If we see the SAME IP address suddenly associated with DIFFERENT MAC addresses,
  that's suspicious and likely an ARP spoofing attempt
- We use a threshold to avoid false positives from legitimate MAC changes (like DHCP renewals)
"""

# Imports here
import time
from collections import defaultdict
from scapy.layers.l2 import ARP
from .centralized_detector import centralized_detector

# arp_spoof_detector class here
class arp_spoof_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        # Initialize parent class (needed for alert functionality)
        super().__init__(app_config, alert_manager)
        
        # Configuration from config.yaml
        self.window = app_config.window_seconds  # Time window to track changes
        self.threshold = app_config.arp_mac_change_threshold  # How many MAC changes trigger alert
        
        # Data structures to track ARP behavior
        self.ip_mac_map = defaultdict(set)  # IP -> set of MAC addresses seen
        self.mac_change_times = defaultdict(list)  # IP -> list of timestamps when MAC changed

    def analyze_packet(self, packet):
        # Step 1: Check if the packet is ARP
        if ARP not in packet:
            return
        
        arp_layer = packet.getlayer(ARP)
        if arp_layer is None:
            return
        
        # Step 2: Extract sender's IP and MAC from ARP packet 
        ip = arp_layer.psrc  # Source IP address
        mac = arp_layer.hwsrc  # Source MAC address

        # Step 3: Detect MAC address changes (potential spoofing)
        known_macs = self.ip_mac_map[ip]  # Get the set of MACs seen for this IP

        # Check if this IP has been seen before (set is not empty)
        if len(known_macs) > 0:
            # IP has been seen before --> check if the MAC is different
            if mac not in known_macs:
                # MAC has changed --> Could be sus --> record the timestamp
                current_time = time.time()
                self.mac_change_times[ip].append(current_time)
        
        # Always add this MAC to our records (whether first time or change)
        known_macs.add(mac)

        # Step 4: Implement sliding window --> remove all the old (irrelevant) MAC-change timestamps
        now = time.time()
        change_times = self.mac_change_times[ip]  # Get list of timestamps for this IP
        
        # Create a new list to store only recent timestamps (within the window)
        recent_changes = []
        for timestamp in change_times:
            # Check if this timestamp is within our time window
            if (now - timestamp) <= self.window:
                recent_changes.append(timestamp)  # Keep it

            # If not within window --> ignore it (it gets filtered out)
        
        # Update records with only the recent changes
        self.mac_change_times[ip] = recent_changes

        # Step 5: Check if the number of MAC changes exceeds our threshold
        count = len(self.mac_change_times[ip])  # Number of recent MAC changes for this IP

        # If count exceeds threshold --> ARP spoofing attack detected
        if count >= self.threshold:
            self.alert({
                'detector': 'arp_spoof',  # Detector name
                'ip': ip,  # IP address being spoofed
                'mac': mac,  # Current MAC address
                'known_macs': list(known_macs),  # All MAC addresses seen for this IP
                'mac_changes': count,  # Number of MAC changes detected
                'window_seconds': self.window,  # Time window for these changes
                'message': (
                    f'ARP spoofing detected! IP {ip} has been associated with '
                    f'{count} different MAC addresses in {self.window} seconds. '
                    f'Current MAC: {mac}, All MACs seen: {list(known_macs)}'
                )
            })

            # Clear the recorded changes to avoid repeated alerts for the same event
            self.mac_change_times[ip].clear()
