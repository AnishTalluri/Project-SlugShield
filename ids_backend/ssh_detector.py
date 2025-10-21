# ids_backend/ssh_detector.py
from scapy.layers.inet import TCP, IP
import logging
import time
from collections import defaultdict, deque

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
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        # Only consider TCP SYN packets to port 22
        if tcp.dport != 22:
            return
        # SYN flag only (0x02), ignore packets that are not connection attempts
        if not (tcp.flags & 0x02):
            return

        src = ip.src
        if src in IGNORE_IPS:
            return

        now = time.time()
        dq = _recent_attempts[src]
        dq.append(now)
        _prune_deque(dq, now)

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
