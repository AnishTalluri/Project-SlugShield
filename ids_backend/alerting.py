# ids_backend/alerting.py
from typing import Dict, Any, Set
from collections import deque
import asyncio
import time

from ids_backend.email_utils import send_email_notification
from ids_backend.state import current_email   # correct shared state


class alert_broadcaster:
    """
    Manages WebSocket connections and distributes alerts + stats + email notifications.
    """

    def __init__(self, max_alerts_store: int = 1000, max_stats_stored: int = 600):
        self.recent_alerts = deque(maxlen=max_alerts_store)
        self.recent_stats = deque(maxlen=max_stats_stored)
        self.connections: Set = set()
        self._lock = asyncio.Lock()

    async def register(self, websocket):
        async with self._lock:
            self.connections.add(websocket)

    async def unregister(self, websocket):
        async with self._lock:
            self.connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        async with self._lock:
            connections = list(self.connections)

        data = json.dumps(message)
        disconnected = []

        for ws in connections:
            try:
                await ws.send_text(data)
            except Exception:
                disconnected.append(ws)

        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self.connections.discard(ws)

    # ----------------------------------------------------------------------
    # PUSH ALERT
    # ----------------------------------------------------------------------
    async def push_alert(self, alert: Dict[str, Any]):
        """Store alert, broadcast it, and send email if needed."""
        self.recent_alerts.append(alert)

        # ================================================================
        #  EMAIL: SSH BRUTE-FORCE DETECTION
        # ================================================================
        if alert.get("detector") == "ssh_bruteforce" and current_email["address"]:
            subject = "SSH Brute-Force Attack Detected"

            message = (
                "SSH Brute-Force Detection (Simple Explanation)\n"
                "\n"
                "The SSH brute-force detector watches for people trying to break into your "
                "computer by repeatedly guessing your password. Normally, someone logs in once, "
                "maybe twice. But an attacker may try dozens of attempts very quickly.\n"
                "\n"
                "The detector monitors how many SSH login attempts occur in a short time. "
                "If that number becomes unusually high, it warns you.\n"
                "\n"
                "In simple terms:\n"
                "• It checks how many times someone tries to log in\n"
                "• It looks for unusually fast repeated attempts\n"
                "• It alerts you if someone may be trying to break in\n"
                "\n"
                "--------------------------------------------------\n"
                "Alert Details:\n"
                f"• Source IP: {alert.get('src')}\n"
                f"• Message: {alert.get('message')}\n"
                f"• Timestamp: {time.ctime(alert.get('timestamp'))}\n"
                "--------------------------------------------------\n"
            )

            send_email_notification(subject, message, current_email["address"])



        # ================================================================
        #  EMAIL: ICMP FLOOD DETECTION
        # ================================================================
        if alert.get("detector") == "icmp_flood" and current_email["address"]:
            subject = "ICMP Flood Attack Detected"

            message = (
                "ICMP Flood Detection (Simple Explanation)\n"
                "\n"
                "An ICMP flood occurs when someone sends a huge number of ping packets "
                "(ICMP Echo Requests) to overload your network. Pings are normally harmless, "
                "but too many at once can slow down or freeze a device.\n"
                "\n"
                "Your ICMP flood detector watches how many ICMP packets arrive per second. "
                "If the number suddenly spikes far above normal levels, it may indicate an "
                "attempt to overwhelm your system.\n"
                "\n"
                "In simple terms:\n"
                "• It counts how many ICMP packets (pings) hit your system\n"
                "• It notices when the number becomes extremely high\n"
                "• It warns you if someone may be trying to overload your network\n"
                "\n"
                "--------------------------------------------------\n"
                "Alert Details:\n"
                f"• Source IP: {alert.get('src', 'Unknown')}\n"
                f"• Packet Rate: {alert.get('rate', 'N/A')} packets/sec\n"
                f"• Timestamp: {time.ctime(alert.get('timestamp'))}\n"
                "--------------------------------------------------\n"
            )

            send_email_notification(subject, message, current_email["address"])


        # Broadcast to dashboard WebSocket
        await self.broadcast({"type": "alert", "payload": alert})

    # ----------------------------------------------------------------------
    # PUSH STAT
    # ----------------------------------------------------------------------
    async def push_stat(self, stat: Dict[str, Any]):
        self.recent_stats.append(stat)
        await self.broadcast({"type": "stat", "payload": stat})

    # ----------------------------------------------------------------------
    # GETTERS
    # ----------------------------------------------------------------------
    def get_alerts(self, limit: int = 100):
        return list(self.recent_alerts)[-limit:]

    def get_stats(self, metric: str, since_seconds: int = 60):
        cutoff = time.time() - since_seconds
        return [
            s for s in self.recent_stats
            if s.get("metric") == metric and s.get("timestamp", 0) >= cutoff
        ]


# Shared broadcaster instance
broadcaster = alert_broadcaster()
