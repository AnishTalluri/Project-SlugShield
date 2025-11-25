# ids_backend/ssh_detector.py
from scapy.layers.inet import TCP, IP
import logging
import time
from collections import defaultdict, deque
import asyncio

# Import broadcaster for dashboard alerts and stats
from ids_backend.alerting import broadcaster

# ----------------------------
# Logging Configuration
# ----------------------------
logging.basicConfig(
    filename="detections.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ----------------------------
# Parameters & State
# ----------------------------
THRESHOLD = 10            # Number of SSH attempts before alert
WINDOW = 60               # Seconds for sliding window
ALERT_COOLDOWN = 300      # Seconds to suppress subsequent alerts per source (5 minutes)
IGNORE_IPS = {"127.0.0.1", "169.233.192.122"}  # Add known-safe IPs here

# per-src deque of timestamps
_recent_attempts = defaultdict(deque)
# per-src timestamp when last alerted
_alerted_srcs = {}  # src_ip -> last_alert_epoch
# timestamp of last stat push
_last_stat_time = 0


# ----------------------------
# Helper: prune deque
# ----------------------------
def _prune_deque(dq, now):
    cutoff = now - WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()


# ----------------------------
# Detector Function
# ----------------------------
def ssh_detector(packet):
    """
    Detect repeated SSH connection attempts:
     - Count SYN packets to TCP dst port 22 per source IP using a sliding window.
     - Raise an alert once per ALERT_COOLDOWN seconds per source IP.
     - Push live SSH attempt rates to dashboard.
    """
    global _last_stat_time
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        # Only consider TCP SYN packets to port 22
        if tcp.dport != 22:
            return

        # SYN flag only (0x02)
        if not (tcp.flags & 0x02):
            return

        src = ip.src
        if src in IGNORE_IPS:
            return

        now = time.time()
        dq = _recent_attempts[src]
        dq.append(now)
        _prune_deque(dq, now)

        # Push SSH attempt stats every second
        if now - _last_stat_time >= 1:
            total_attempts = sum(len(v) for v in _recent_attempts.values())
            try:
                broadcaster.push_stat({
                    "metric": "ssh_attempts_per_second",
                    "timestamp": now,
                    "value": total_attempts / WINDOW,
                })
            except Exception as e:
                logging.error(f"Failed to push ssh stat: {e}")
            _last_stat_time = now

        # If threshold reached and cooldown passed -> alert
        if len(dq) >= THRESHOLD:
            last_alert = _alerted_srcs.get(src, 0)
            if now - last_alert >= ALERT_COOLDOWN:
                msg = f"[ALERT] Repeated SSH login attempts from {src}: {len(dq)} attempts in {WINDOW}s"
                print(msg)
                logging.warning(msg)
                _alerted_srcs[src] = now

                # Send alert to dashboard
                try:
                    alert_data = {
                        "timestamp": now,
                        "severity": "high",
                        "detector": "ssh_bruteforce",
                        "src": src,
                        "message": msg
                    }

                    # Handle async broadcaster correctly
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(broadcaster.push_alert(alert_data))
                    else:
                        asyncio.run(broadcaster.push_alert(alert_data))

                except Exception as e:
                    err = f"Failed to push ssh alert to broadcaster: {e}"
                    print(f"[ERROR] {err}")
                    logging.error(err)

                dq.clear()
            else:
                dq.clear()

    except Exception as e:
        err = f"SSH detector exception: {e}"
        print(f"[ERROR] {err}")
        logging.error(err)
