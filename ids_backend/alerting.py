# ids_backend/alerting.py

import asyncio
import json
import time
from collections import deque
from typing import List, Dict, Any

class alert_broadcaster:
    def __init__(self, max_alerts_store=1000, max_stats_stored=600):
        self.recent_alerts = deque(maxlen=max_alerts_store)
        self.recent_stats = deque(maxlen=max_stats_stored)
        self.connections = set()

    async def register(self, websocket):
        self.connections.add(websocket)

    async def unregister(self, websocket):
        self.connections.discard(websocket)

    async def broadcast(self, message: dict):
        if not self.connections:
            return

        data = json.dumps(message)
        to_remove = []
        for websocket_client in self.connections:
            try:
                await websocket_client.send_text(data)
            except Exception:
                to_remove.append(websocket_client)

        for websocket_client in to_remove:
            self.connections.discard(websocket_client)

    # Helper used by both alerts & stats
    def _schedule_broadcast(self, message: dict):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop running (e.g., CLI tests) -> keep history but don't broadcast
            return
        else:
            loop.create_task(self.broadcast(message))

    # ---- Make this synchronous ----
    def push_alert(self, alert: Dict[str, Any]):
        self.recent_alerts.append(alert)
        self._schedule_broadcast({"type": "alert", "payload": alert})

    # ---- Also make this synchronous ----
    def push_stat(self, stat: Dict[str, Any]):
        self.recent_stats.append(stat)
        self._schedule_broadcast({"type": "stat", "payload": stat})

    def get_alerts(self, limit=100):
        return list(self.recent_alerts)[-limit:]

    def get_stats(self, metric="icmp_packets_per_second", since_seconds=60):
        cutoff = time.time() - since_seconds
        return [
            s for s in self.recent_stats
            if s["metric"] == metric and s["timestamp"] >= cutoff
        ]

broadcaster = alert_broadcaster()


