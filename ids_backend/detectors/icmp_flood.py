import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
<<<<<<< HEAD
from ..centralized_detector import centralized_detector
from ..alerting import broadcaster

class icmp_counter_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)
        self.window = float(app_config.window_seconds)
        self.threshold = int(app_config.icmp_threshold_per_window)
        self.events = defaultdict(lambda: deque()) # This is to keep a mapping of each source IP to a deque timestamp of ICMP packet
        self.last_stat_time = 0 # periodic stat reporting
        self.alert_manager = alert_manager

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

        print(f"Detector received ICMP from {source_ip}")

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

=======

from ..centralized_detector import centralized_detector
from ..alerting import broadcaster


class icmp_counter_detector(centralized_detector):
    """
    Improved ICMP flood detector.
    - Tracks packets per *source*
    - Reports accurate packets/sec to dashboard
    - Triggers flood alerts based on packets/sec (not per-window count)
    """

    def __init__(self, app_config, alert_manager):
        super().__init__(app_config, alert_manager)

        self.window_seconds = float(app_config.window_seconds)   # normally 60s
        self.threshold = int(app_config.icmp_threshold_per_window)  # UI value
        self.events = defaultdict(lambda: deque())               # timestamps per IP
        self.last_stat_push = 0
        self.alert_manager = alert_manager

    # ---------------------------------------------------------
    # Process incoming packets
    # ---------------------------------------------------------
    def analyze_packet(self, packet):

        now = time.time()
        src_ip = None

        # IPv4 ICMP
        ip4 = packet.getlayer(IP)
        if ip4 is not None and ICMP in packet:
            src_ip = ip4.src

        else:
            # IPv6 ICMP
            ip6 = packet.getlayer(IPv6)
            if ip6 is not None and (ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet):
                src_ip = ip6.src

        if not src_ip:
            return  # not ICMP

        # Record event
        dq = self.events[src_ip]
        dq.append(now)

        # Sliding window cleanup
        while dq and now - dq[0] > self.window_seconds:
            dq.popleft()

        # ---------------------------------------------------------
        # PACKETS PER SECOND (what the dashboard expects)
        # ---------------------------------------------------------
        total_packets_last_second = sum(
            len([ts for ts in timestamps if now - ts <= 1.0])
            for timestamps in self.events.values()
        )

        # ---------------------------------------------------------
        # Send live stats once per second
        # ---------------------------------------------------------
        if now - self.last_stat_push >= 1:
            stat = {
                "metric": "icmp_packets_per_second",
                "timestamp": now,
                "value": total_packets_last_second,
            }
            broadcaster.push_stat(stat)
            self.last_stat_push = now

        # ---------------------------------------------------------
        # FLOOD ALERT (based on packets per SECOND, not per window)
        # ---------------------------------------------------------
        if total_packets_last_second >= self.threshold:

            alert_data = {
                "timestamp": now,
                "severity": "high",
                "detector": "icmp_flood",
                "src": src_ip,
                "pps": total_packets_last_second,
                "message": f"ICMP flood detected from {src_ip}: {total_packets_last_second} packets/sec"
            }

            # Push to SNS/Email system
            self.alert(alert_data)

            # Push to dashboard websocket
            broadcaster.push_alert(alert_data)

            # Clear offender's timestamps so alerts don't spam constantly
            dq.clear()
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
