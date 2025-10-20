import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, ICMP
from ..centralized_detector import centralized_detector

class icmp_counter_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)
        self.window = app_config.window_seconds
        self.threshold = app_config.icmp_threshold_per_window
        self.events = defaultdict(lambda: deque()) # This is to keep a mapping of each source IP to a deque timestamp of ICMP packet

    def analyze_packet(self, packet):
        now = time.time()
        ip_layer = packet.getlayer(IP)
        if ip_layer is None:
            return # Return early if no ip header
        
        if ICMP not in packet:
            return # This file is only for detecting icmp flooding
        
        # The mapping concept from __init__
        source_ip = ip_layer.src
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