from scapy.all import sniff, get_if_list, conf
import sys

class PacketCapture:
    def __init__(self, app_config):
        self.interface = self._get_interface(app_config.interface)
        self.store_detectors = [] # Store detectors like icmp flooding, port scan, etc. 
        self.running = False # Track whether packet capture is active
    
    def _get_interface(self, configured_interface):
        """
        Determine which network interface to use.
        If configured_interface is None, auto-detect the best interface.
        """
        if configured_interface:
            # User specified an interface
            return configured_interface
        
        # Auto-detect interface
        available_interfaces = get_if_list()
        
        # Try to find the best interface for different platforms
        # Priority: eth0 (Linux/WSL), en0 (macOS), then first non-loopback
        priority_interfaces = ['eth0', 'en0', 'wlan0', 'Wi-Fi', 'Ethernet']
        
        for iface in priority_interfaces:
            if iface in available_interfaces:
                print(f"Auto-detected network interface: {iface}")
                return iface
        
        # Fall back to scapy's default or first available non-loopback
        for iface in available_interfaces:
            if 'lo' not in iface.lower() and 'loopback' not in iface.lower():
                print(f"Auto-detected network interface: {iface}")
                return iface
        
        # Last resort: use scapy's default
        print(f"Using default interface: {conf.iface}")
        return None  # None tells scapy to use its default

    # This function is utilized to add our detections-- pass in the detection you're working on as paramter
    def add_detection(self, detector):
        self.store_detectors.append(detector)

    # Pass every packet to each detector in store_detectors
    def process_packet_in_detector(self, packet):
        for store_detector in self.store_detectors:
            try:
                store_detector(packet)
            except Exception as e:
                print(f'Error with detector: {e}')
        
    # Sniff the packets
    def start_sniff(self):
        self.running = True
        # Capture ICMP, ARP, and TCP packets for multi-detector support
        bpf = 'icmp or arp or tcp'
        # Captures packets in real time 
        sniff(filter = bpf, prn = self.process_packet_in_detector, store = False, iface = self.interface)
    
    # Sniff ARP packets specifically --> Anish added this for testing the ARP spoofer (obviously lol)
    def start_sniff_arp(self):
        self.running = True
        bpf = 'arp'
        # Captures ARP packets in real time
        print(f"Starting ARP packet capture on interface: {self.interface or 'default'}")
        sniff(filter = bpf, prn = self.process_packet_in_detector, store = False, iface = self.interface)

    # Stop packet capture-- I don't see a need in this for my part but maybe ya'll need it
    def stop_sniff(self):
        self.running = False
        print("Stop packet capture")