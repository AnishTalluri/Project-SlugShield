import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from ..centralized_detector import centralized_detector

class icmp_counter_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)
        self.window = float(app_config.window_seconds)
        self.threshold = int(app_config.icmp_threshold_per_window)
        self.events = defaultdict(lambda: deque()) # This is to keep a mapping of each source IP to a deque timestamp of ICMP packet

    def analyze_packet(self, packet):
        now = time.time()
        ip4 = packet.getlayer(IP)
        if ip4 is not None and ICMP in packet:
            source_ip = ip4.src
        else:
            # Try IPv6 ICMPv6 (Echo Request/Reply)
            ip6 = packet.getlayer(IPv6)
            if ip6 is not None and (ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet):
                source_ip = ip6.src
            else:
                # Not an ICMP packet
                return

        #print(f"Detector received ICMP from {source_ip}")

        # The mapping concept from __init__
        dq = self.events[source_ip]
        dq.append(now)

        # Sliding window concept
        while dq and (now - dq[0] > self.window):
            dq.popleft()
        count = len(dq)

        # ICMP flood detected, add to alert
        if count >= self.threshold:
            self.alert({
                'detector': 'icmp_flood',
                'src': source_ip,
                'count': count,
                'window_seconds': self.window,
                'message': f'ICMP flood detected from {source_ip}: {count} packets in {self.window}sec'
            })
            dq.clear()