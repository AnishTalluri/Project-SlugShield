<<<<<<< HEAD
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from ids_backend import alerting

app = FastAPI(title = "IDS API")

# Allow cross-origin resource sharing -> to avoid browsers blockings requests due to same-origin policy
app.add_middleware(
    CORSMiddleware, 
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

# Endpoint used by frontend to load recent alerts when dashboard first loads
@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    alerts = alerting.broadcaster.get_alerts(limit = limit)
    return {"alerts": alerts}

# Endpoint used by frontend to plot charts of recent ICMP packet rates
@app.get("/api/stats/icmp")
def get_icmp_stats(interval: int = 60):
    stats = alerting.broadcaster.get_stats(metric = "icmp_packets_per_second", since_seconds = interval)
    return {"stats": stats}

# Websocket endpoint for alerts and stats in real time
@app.websocket("/websocket/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await alerting.broadcaster.register(websocket)

    # Try to populate as soon as client joins
    try:
        # json message with last 20 alerts and last 60 seconds of icmp packets per second
        await websocket.send_json({"type": "init", "alerts": alerting.broadcaster.get_alerts(20)})
        await websocket.send_json({"type": "init_stats", "stats": alerting.broadcaster.get_stats("icmp_packets_per_second", 60)})

        # Keep connection alive
        while True:
            await websocket.receive_text()

    # If disconnects, remove client
    except WebSocketDisconnect:
        await alerting.broadcaster.unregister(websocket)
=======
# ids_backend/api.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from ids_backend.alerting import broadcaster
from ids_backend.config import thresholds
from ids_backend.state import current_email      # <-- the ONLY source of truth
from ids_backend.email_utils import send_email_notification
import time

router = APIRouter()

# ============================================================
# EMAIL ROUTES
# ============================================================

class EmailUpdate(BaseModel):
    email: str

@router.post("/api/set_email")
def set_email(update: EmailUpdate):
    """Set the user's preferred alert email address."""
    current_email["address"] = update.email
    return {"status": "ok", "email": update.email}

# ============================================================
# THRESHOLD UPDATE
# ============================================================

class ThresholdUpdate(BaseModel):
    detector_name: str
    new_value: int

@router.post("/set_threshold")
def set_threshold(update: ThresholdUpdate):
    if update.detector_name not in thresholds:
        return {"status": "error", "message": "Unknown detector"}

    thresholds[update.detector_name] = update.new_value
    return {"status": "ok", "thresholds": thresholds}

# ============================================================
# API ENDPOINTS
# ============================================================

@router.get("/api/alerts")
def get_alerts(limit: int = 100):
    alerts = broadcaster.get_alerts(limit=limit)
    return {"alerts": alerts}

@router.get("/api/stats/icmp")
def get_icmp_stats(interval: int = 60):
    stats = broadcaster.get_stats(
        metric="icmp_packets_per_second",
        since_seconds=interval
    )
    return {"stats": stats}

@router.get("/api/stats/ssh")
def get_ssh_stats(interval: int = 60):
    stats = broadcaster.get_stats(
        metric="ssh_attempts_per_second",
        since_seconds=interval
    )
    return {"stats": stats}

# ============================================================
# WEBSOCKET
# ============================================================

@router.websocket("/websocket/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await broadcaster.register(websocket)

    try:
        await websocket.send_json({
            "type": "init",
            "alerts": broadcaster.get_alerts(20)
        })

        all_stats = []
        for metric in ["icmp_packets_per_second", "ssh_attempts_per_second"]:
            all_stats.extend(broadcaster.get_stats(metric, 60))

        await websocket.send_json({
            "type": "init_stats",
            "stats": all_stats
        })

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        await broadcaster.unregister(websocket)

# ============================================================
# TEST ALERTS / EMAIL
# ============================================================

@router.post("/api/test/ssh")
async def test_ssh_alert():
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

@router.post("/api/test/icmp_alert")
async def test_icmp_alert():
    now = time.time()
    alert_data = {
        "timestamp": now,
        "severity": "high",
        "detector": "icmp_flood",
        "src": "10.0.0.167",
        "rate": 500,   # simulated pps
        "message": "[TEST] Simulated ICMP flood alert"
    }

    await broadcaster.push_alert(alert_data)
    return {"status": "ok", "alert": alert_data}



# ============================================================
# UPDATED EMAIL TEST (with full explanation)
# ============================================================

@router.post("/api/test/email/ssh")
def test_email_ssh():
    if not current_email["address"]:
        return {"status": "error", "message": "No email set"}

    send_email_notification(
        subject="🔥 TEST — SSH Brute-Force Notification",
        message=(
            "SSH Brute-Force Detection (Simple Explanation)\n"
            "\n"
            "The SSH brute-force detector is a tool that watches for people trying to "
            "break into your computer by guessing your password over and over. Normally, "
            "someone logging in would try once, maybe twice if they mistype. But an attacker "
            "might try many times quickly, hoping one password will work.\n"
            "\n"
            "This detector keeps track of how many login attempts happen in a short amount "
            "of time. If it sees a lot of attempts happening really fast, it assumes something "
            "suspicious is going on and sends an alert.\n"
            "\n"
            "In simple terms:\n"
            "• It checks how many times someone tries to log in\n"
            "• It notices when the number is unusually high\n"
            "• It warns you if it looks like someone might be trying to force their way in\n"
            "\n"
            "It’s basically a way to spot when someone might be trying to access your computer "
            "without permission.\n"
            "\n"
            "This is a TEST email to confirm that your SSH notification system is working.\n"
        ),
        recipient=current_email["address"]
    )

    return {"status": "sent", "to": current_email["address"]}


@router.get("/api/debug/email")
def debug_email():
    return {"email": current_email["address"]}

@router.post("/api/test/stats")
async def test_stats():
    now = time.time()

    icmp_stat = {
        "timestamp": now,
        "metric": "icmp_packets_per_second",
        "value": 12.4,
    }
    ssh_stat = {
        "timestamp": now,
        "metric": "ssh_attempts_per_second",
        "value": 5.8,
    }

    await broadcaster.push_stat(icmp_stat)
    await broadcaster.push_stat(ssh_stat)

    return {"status": "ok", "stats": [icmp_stat, ssh_stat]}

# ============================================================
# TEST STATS (for graph debugging)
# ============================================================

@router.post("/api/test/icmp")
async def test_icmp_stat():
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "icmp_packets_per_second",
        "value": 50  # simulate 50 packets/s
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}


@router.post("/api/test/ssh_stat")
async def test_ssh_stat():
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "ssh_attempts_per_second",
        "value": 25  # simulate 25 ssh attempts/s
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
