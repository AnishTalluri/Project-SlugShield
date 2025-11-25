from scapy.all import sniff


class PacketCapture:
    def __init__(self, app_config):
        # Interface to sniff on (e.g., "lo", "enp0s3", or ""/None for default/"any")
        self.interface = getattr(app_config, "interface", None)
        self.store_detectors = []  # Detectors like ARP, port scan, etc.
        self.running = False       # Track whether packet capture is active

    # Add a detector callback (e.g., port_scan_detector.analyze_packet)
    def add_detection(self, detector):
        self.store_detectors.append(detector)

    # Pass every packet to each detector in store_detectors
    def process_packet_in_detector(self, packet):
        for detector in self.store_detectors:
            try:
                detector(packet)
            except Exception:
                # You *can* log here if you want, but don't crash the sniffer.
                pass

    # General sniff (used by your port scan test harness)
    def start_sniff(self):
        self.running = True
        iface = self.interface if self.interface not in (None, "", "auto") else None
        try:
            sniff(
                prn=self.process_packet_in_detector,
                store=False,
                iface=iface,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            print("[CAPTURE][ERROR] Sniff failed:", e)

    # Sniff ARP packets specifically (for the ARP detector test harness)
    def start_sniff_arp(self):
        self.running = True
        bpf = "arp"
        sniff(
            filter=bpf,
            prn=self.process_packet_in_detector,
            store=False,
            iface=self.interface,
        )

    def stop_sniff(self):
        self.running = False


