import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply

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
