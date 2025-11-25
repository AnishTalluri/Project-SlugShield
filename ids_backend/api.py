from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from ids_backend.alerting import broadcaster
import time  # for timestamps

app = FastAPI(title="IDS API")

# Allow CORS (for frontend communication)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# API Endpoints
# ----------------------------

@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    """Return recent alerts for the frontend."""
    alerts = broadcaster.get_alerts(limit=limit)
    return {"alerts": alerts}


@app.get("/api/stats/icmp")
def get_icmp_stats(interval: int = 60):
    """Return recent ICMP traffic metrics."""
    stats = broadcaster.get_stats(metric="icmp_packets_per_second", since_seconds=interval)
    return {"stats": stats}


# ----------------------------
# WebSocket Endpoint
# ----------------------------
@app.websocket("/websocket/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """Handle real-time dashboard updates."""
    await websocket.accept()
    await broadcaster.register(websocket)

    try:
        # Send recent alerts first
        await websocket.send_json({
            "type": "init",
            "alerts": broadcaster.get_alerts(20)
        })

        # Send both ICMP and SSH stats to frontend
        all_stats = []
        for metric in ["icmp_packets_per_second", "ssh_attempts_per_second"]:
            all_stats.extend(broadcaster.get_stats(metric, 60))

        await websocket.send_json({
            "type": "init_stats",
            "stats": all_stats
        })

        # Keep connection alive
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        await broadcaster.unregister(websocket)


# ----------------------------
# Test Endpoints
# ----------------------------

@app.post("/api/test/ssh")
async def test_ssh_alert():
    """Simulated SSH brute-force alert for testing dashboard."""
    now = time.time()
    alert_data = {
        "timestamp": now,
        "severity": "high",
        "detector": "ssh_bruteforce",
        "src": "192.168.1.55",
        "message": "[TEST] Simulated SSH brute-force alert",
    }
    await broadcaster.push_alert(alert_data)
    return {"status": "ok", "alert": alert_data}


@app.post("/api/test/icmp")
async def test_icmp_alert():
    """Simulated ICMP flood alert for testing dashboard."""
    now = time.time()
    alert_data = {
        "timestamp": now,
        "severity": "medium",
        "detector": "icmp_flood",
        "src": "10.0.0.15",
        "message": "[TEST] Simulated ICMP flood alert",
    }
    await broadcaster.push_alert(alert_data)
    return {"status": "ok", "alert": alert_data}


@app.post("/api/test/stats")
async def test_stats():
    """Simulated ICMP + SSH traffic metrics for chart testing."""
    now = time.time()

    icmp_stat = {
        "timestamp": now,
        "metric": "icmp_packets_per_second",
        "value": 15.2,
    }
    ssh_stat = {
        "timestamp": now,
        "metric": "ssh_attempts_per_second",
        "value": 3.7,
    }

    await broadcaster.push_stat(icmp_stat)
    await broadcaster.push_stat(ssh_stat)

    return {"status": "ok", "stats": [icmp_stat, ssh_stat]}
