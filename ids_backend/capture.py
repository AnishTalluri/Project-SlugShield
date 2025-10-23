from scapy.all import sniff

class PacketCapture:
    def __init__(self, app_config):
        self.interface = app_config.interface
        self.store_detectors = [] # Store detectors like icmp flooding, port scan, etc. 
        self.running = False # Track whether packet capture is active

    # This function is utilized to add our detections-- pass in the detection you're working on as paramter
    def add_detection(self, detector):
        self.store_detectors.append(detector)

    # Pass every packet to each detector in store_detectors
    def process_packet_in_detector(self, packet):
        '''
        # Debug: print a short summary so we know sniff() is delivering packets
        try:
            print("CAPTURED PKT summary:", packet.summary())
        except Exception:
            print("CAPTURED PKT (couldn't summary)")
        '''
        for store_detector in self.store_detectors:
            try:
                store_detector(packet)
            except Exception as e:
                print(f'Error with detector: {e}')
        
    # Sniff the packets
    def start_sniff(self):
        self.running = True
        #bpf = 'icmp or icmp6' 
        #print(f"Starting sniff on iface={self.interface}, bpf='{bpf}'")
        # Captures packets in real time 
        try:
            sniff(prn=self.process_packet_in_detector, store=False, iface=self.interface)
        except Exception as e:
            print("Sniff failed:", e)
    
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