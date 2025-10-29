import json
import time
import asyncio
from collections import deque
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