# ids_backend/ssh_detector.py
from scapy.layers.inet import TCP, IP
import logging
import time
from collections import defaultdict, deque
<<<<<<< HEAD

# ----------------------------
# Logging Configuration
# ----------------------------
=======
import asyncio

from ids_backend.alerting import broadcaster
from ids_backend.config import thresholds

>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
logging.basicConfig(
    filename="detections.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

<<<<<<< HEAD
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

# ----------------------------
# Helper: prune deque
# ----------------------------
=======
WINDOW = 60
ALERT_COOLDOWN = 300
IGNORE_IPS = {"127.0.0.1", "169.233.192.122"}

_recent_attempts = defaultdict(deque)
_alerted_srcs = {}
_last_stat_time = 0


>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
def _prune_deque(dq, now):
    cutoff = now - WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()

<<<<<<< HEAD
# ----------------------------
# Detector Function
# ----------------------------
def ssh_detector(packet):
    """
    Detect repeated SSH connection attempts:
     - Count SYN packets to TCP dst port 22 per source IP using a sliding window.
     - Raise an alert once per ALERT_COOLDOWN seconds per source IP.
    """
=======

def ssh_detector(packet):
    """
    SSH brute-force detection + SSH attempts/s stats for graph.
    """
    global _last_stat_time

>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

<<<<<<< HEAD
        # Only consider TCP SYN packets to port 22
        if tcp.dport != 22:
            return
        # SYN flag only (0x02), ignore packets that are not connection attempts
        if not (tcp.flags & 0x02):
=======
        # listen for TCP SYN to port 22
        if tcp.dport != 22 or not (tcp.flags & 0x02):
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
            return

        src = ip.src
        if src in IGNORE_IPS:
            return

        now = time.time()
<<<<<<< HEAD
=======

        # Track attempts
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
        dq = _recent_attempts[src]
        dq.append(now)
        _prune_deque(dq, now)

<<<<<<< HEAD
        # If we haven't alerted recently for this src and threshold reached -> alert
        if len(dq) >= THRESHOLD:
            last_alert = _alerted_srcs.get(src, 0)
            if now - last_alert >= ALERT_COOLDOWN:
                msg = f"[ALERT] Repeated SSH login attempts from {src}: {len(dq)} attempts in {WINDOW}s"
                print(msg)
                logging.warning(msg)
                _alerted_srcs[src] = now
                # clear attempt history to avoid immediate retrigger
                dq.clear()
            else:
                # suppress alert, but still clear attempts so we don't retrigger repeatedly
                dq.clear()

    except Exception as e:
        # keep detector resilient
        err = f"SSH detector exception: {e}"
        print(f"[ERROR] {err}")
        logging.error(err)
=======
        # ---------------------------------------------------
        # 📈 PUSH SSH ATTEMPTS PER SECOND (for graph)
        # ---------------------------------------------------
        if now - _last_stat_time >= 1:
            total_attempts = sum(len(v) for v in _recent_attempts.values())
            attempts_per_second = total_attempts / WINDOW

            try:
                # Use asyncio.create_task so async function executes correctly
                asyncio.create_task(
                    broadcaster.push_stat({
                        "timestamp": now,
                        "metric": "ssh_attempts_per_second",
                        "value": attempts_per_second,
                    })
                )
            except Exception as e:
                logging.error(f"Failed to push ssh stat: {e}")

            _last_stat_time = now

        # ---------------------------------------------------
        # 🚨 Raise alert if threshold exceeded
        # ---------------------------------------------------
        if len(dq) >= thresholds["ssh"]:
            last_alert = _alerted_srcs.get(src, 0)

            if now - last_alert >= ALERT_COOLDOWN:
                msg = (
                    f"[ALERT] Repeated SSH login attempts from {src}: "
                    f"{len(dq)} attempts in {WINDOW}s"
                )
                print(msg)
                logging.warning(msg)
                _alerted_srcs[src] = now

                alert_data = {
                    "timestamp": now,
                    "severity": "high",
                    "detector": "ssh_bruteforce",
                    "src": src,
                    "message": msg,
                }

                # async alert delivery
                try:
                    asyncio.create_task(broadcaster.push_alert(alert_data))
                except Exception as e:
                    logging.error(f"Failed to push ssh alert: {e}")

                dq.clear()
            else:
                dq.clear()

    except Exception as e:
        logging.error(f"SSH detector exception: {e}")
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
