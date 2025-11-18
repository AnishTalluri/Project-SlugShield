<<<<<<< HEAD
=======
# ids_backend/alerting.py
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
import json
import time
import asyncio
from collections import deque
<<<<<<< HEAD
from typing import List, Dict, Any

class alert_broadcaster:
    def __init__(self, loop: asyncio.AbstractEventLoop, max_alerts_store = 1000, max_stats_stored = 600):
        self.recent_alerts = deque(maxlen = max_alerts_store) # Auto remove oldest alert stored in memory once deque full
        self.recent_stats = deque(maxlen = max_stats_stored) # Same concept as above
        self.connections = set() # Stores all active websocket connections to clients
        self.loop = loop # Stores main event loop

    # Register new websocket connection
    async def register(self, websocket):
        self.connections.add(websocket)

    # Remove websocket when disconnects
    async def unregister(self, websocket):
        self.connections.discard(websocket)

    # Send message to all active client
    async def broadcast(self, message: dict):

        # No active websocket clients connected
        if not self.connections:
            return
        
        # Sends message to all active websocket connections in self.connections
        data = json.dumps(message)
        to_remove = []
        for websocket_client in self.connections:
            try:
                await websocket_client.send_text(data)
            except Exception:
                to_remove.append(websocket_client)

        # Remove all disconnected websocket clients from self.connection set
        for websocket_client in to_remove:
            self.connections.discard(websocket_client)

    # Store new alert and broadcast to connected clients
    def push_alert(self, alert: Dict[str, Any]):
        self.recent_alerts.append(alert)
        asyncio.run_coroutine_threadsafe(self.broadcast({"type": "alert", "payload": alert}), self.loop)

    # Store new ICMP stat and broadcast to connected clients
    def push_stat(self, stat: Dict[str, Any]):
        self.recent_stats.append(stat)
        asyncio.run_coroutine_threadsafe(self.broadcast({"type": "stat", "payload": stat}), self.loop)

    # Return newest alerts 
    def get_alerts(self, limit = 100):
        return list(self.recent_alerts)[-limit:]
    
    # Return stats for last since_seconds
    def get_stats(self, metric = "icmp_packets_per_second", since_seconds = 60):
        cutoff = time.time() - since_seconds

        # filter for only stats that happened in last 60 seconds and stats of given metric icmp_packets_per_seconds
        return [s for s in self.recent_stats if s["metric"] == metric and s["timestamp"] >= cutoff]
    
loop = asyncio.get_event_loop()
broadcaster = alert_broadcaster(loop)
=======
from typing import Dict, Any, Set

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
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
