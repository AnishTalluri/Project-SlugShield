from scapy.all import sniff

class PacketCapture:

    def __init__(self, app_config):
        self.interface = app_config.interface # Network interface to listen on
        self.running = False
        self.detectors = []

    # Add detector to distribute packets to 
    def add_detection(self, callback):
        self.detectors.append(callback)

    # Process packets
    def process_packet(self, packet):
        for detector in self.detectors:
            try:
                detector(packet)
            except Exception as e:
                print(f"[Detector Error] {e}")

    # Capture packets
    def start_sniff(self):
        self.running = True
        print(f"[Sniffer] Listening on interface: {self.interface}")

        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
            )
        except Exception as e:
            print(f"[Sniffer Error] {e}")

    # Stop sniffing for packets
    def stop_sniff(self):
        self.running = False
        print("[Sniffer] Stopped.")