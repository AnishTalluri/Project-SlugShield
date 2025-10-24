import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from ..centralized_detector import centralized_detector
from ..alerting import broadcaster

class icmp_counter_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)
        self.window = float(app_config.window_seconds)
        self.threshold = int(app_config.icmp_threshold_per_window)
        self.events = defaultdict(lambda: deque()) # This is to keep a mapping of each source IP to a deque timestamp of ICMP packet
        self.last_stat_time = 0 # periodic stat reporting

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

        # Sends packet rate stats every 1 second for live chart
        if now - self.last_stat_time >= 1:
            total_packets = sum(len(v) for v in self.events.values())

            # Sends to broadcaster
            broadcaster.push_stat({
                "metric": "icmp_packets_per_second",
                "timestamp": now,
                "value": total_packets / self.window,
            })
            self.last_stat_time = now

        # ICMP flood detected, add to alert
        if count >= self.threshold:
            alert_data = {
                'detector': 'icmp_flood',
                'src': source_ip,
                'count': count,
                'window_seconds': self.window,
                'message': f'ICMP flood detected from {source_ip}: {count} packets in {self.window}sec'
            }

            self.alert(alert_data)

            # Push same alert to broadcaster for dashboard
            broadcaster.push_alert({
                "timestamp": now, 
                "severity": "high",
                **alert_data
            })

            dq.clear()

