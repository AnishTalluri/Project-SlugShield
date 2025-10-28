"""
SSH Brute Force Detector

Detects repeated SSH login attempts that may indicate a brute force attack.
Monitors TCP SYN packets to port 22 (SSH) and tracks attempts per source IP.
"""

# ids_backend/ssh_detector.py
from scapy.layers.inet import TCP, IP
import logging
import time
from collections import defaultdict, deque
from .centralized_detector import centralized_detector

# TODO: Re-enable broadcaster when dashboard is ready
# from ids_backend.alerting import broadcaster
# print("Broadcaster ID (SSH):", id(broadcaster))


class ssh_bruteforce_detector(centralized_detector):
    def __init__(self, app_config, alert_manager):
        """
        Initialize SSH brute force detector.
        
        Args:
            app_config: Configuration object with detection parameters
            alert_manager: Manager for sending alerts when attacks are detected
        """
        super().__init__(app_config, alert_manager)
        
        # Configuration parameters
        self.window = app_config.window_seconds  # Time window to track attempts
        self.threshold = getattr(app_config, 'ssh_threshold_per_window', 10)  # SSH attempts threshold
        self.alert_cooldown = 300  # 5 minutes between alerts for same IP
        
        # IPs to ignore (localhost, internal services, etc.)
        self.ignore_ips = {"127.0.0.1", "169.233.192.122"}
        
        # Track SSH attempts per source IP
        self._recent_attempts = defaultdict(deque)  # IP -> deque of timestamps
        self._alerted_srcs = {}  # IP -> last alert timestamp
        self._last_stat_time = 0
    
    def _prune_deque(self, dq, now):
        """Remove timestamps outside the sliding window."""
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
    
    def analyze_packet(self, packet):
        """
        Analyze incoming packet for SSH brute force attempts.
        
        Detects:
        - Multiple TCP SYN packets to port 22 (SSH)
        - From the same source IP
        - Within the configured time window
        """
        try:
            # Check if packet has IP and TCP layers
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return
            
            ip = packet[IP]
            tcp = packet[TCP]
            
            # Only consider TCP packets to port 22 (SSH)
            if tcp.dport != 22:
                return
            
            # Only consider SYN packets (connection attempts)
            # SYN flag is 0x02
            if not (tcp.flags & 0x02):
                return
            
            src = ip.src
            
            # Ignore whitelisted IPs
            if src in self.ignore_ips:
                return
            
            now = time.time()
            
            # Track this attempt
            dq = self._recent_attempts[src]
            dq.append(now)
            
            # Remove old attempts outside the time window
            self._prune_deque(dq, now)
            
            # TODO: Push SSH attempt stats to dashboard when broadcaster is ready
            # if now - self._last_stat_time >= 1:
            #     total_attempts = sum(len(v) for v in self._recent_attempts.values())
            #     stat_data = {
            #         "metric": "ssh_attempts_per_second",
            #         "timestamp": now,
            #         "value": total_attempts / self.window,
            #     }
            #     await broadcaster.push_stat(stat_data)
            #     self._last_stat_time = now
            
            # Check if threshold exceeded
            if len(dq) >= self.threshold:
                # Check cooldown to avoid alert spam
                last_alert = self._alerted_srcs.get(src, 0)
                
                if now - last_alert >= self.alert_cooldown:
                    # Trigger alert
                    self.alert({
                        'detector': 'ssh_bruteforce',
                        'src': src,
                        'attempts': len(dq),
                        'window_seconds': self.window,
                        'message': (
                            f'SSH brute force detected from {src}: '
                            f'{len(dq)} connection attempts in {self.window} seconds'
                        )
                    })
                    
                    # TODO: Push alert to dashboard when broadcaster is ready
                    # alert_data = {
                    #     "timestamp": now,
                    #     "severity": "high",
                    #     "detector": "ssh_bruteforce",
                    #     "src": src,
                    #     "message": msg
                    # }
                    # await broadcaster.push_alert(alert_data)
                    
                    # Update last alert time and clear attempts
                    self._alerted_srcs[src] = now
                    dq.clear()
                else:
                    # Still in cooldown, just clear to prevent buildup
                    dq.clear()
        
        except Exception as e:
            print(f'[ERROR] SSH detector exception: {e}')

