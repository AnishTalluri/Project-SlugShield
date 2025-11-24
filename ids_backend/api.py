# ids_backend/api.py

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from ids_backend.alerting import broadcaster
from ids_backend.config import thresholds
from ids_backend.state import current_email
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

@router.get("/api/stats/arp")
def get_arp_stats(interval: int = 60):
    stats = broadcaster.get_stats(
        metric="arp_spoofing_attempts_per_second",
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
        for metric in ["icmp_packets_per_second", "ssh_attempts_per_second", "arp_spoofing_attempts_per_second"]:
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
        "rate": 500,
        "message": "[TEST] Simulated ICMP flood alert"
    }

    await broadcaster.push_alert(alert_data)
    return {"status": "ok", "alert": alert_data}

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
            "It's basically a way to spot when someone might be trying to access your computer "
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
        "value": 50
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/icmp_baseline")
async def test_icmp_baseline():
    """Send baseline ICMP traffic (low value for normal activity)"""
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "icmp_packets_per_second",
        "value": 12
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/ssh_stat")
async def test_ssh_stat():
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "ssh_attempts_per_second",
        "value": 25
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/ssh_baseline")
async def test_ssh_baseline():
    """Send baseline SSH traffic (low value for normal activity)"""
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "ssh_attempts_per_second",
        "value": 3
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/arp_stat")
async def test_arp_stat():
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "arp_spoofing_attempts_per_second",
        "value": 8
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/arp_baseline")
async def test_arp_baseline():
    """Send baseline ARP traffic (low value for normal activity)"""
    now = time.time()
    stat = {
        "timestamp": now,
        "metric": "arp_spoofing_attempts_per_second",
        "value": 1
    }
    await broadcaster.push_stat(stat)
    return {"status": "ok", "stat": stat}

@router.post("/api/test/arp_alert")
async def test_arp_alert():
    now = time.time()
    alert_data = {
        "timestamp": now,
        "severity": "high",
        "detector": "arp_spoof",
        "ip": "192.168.1.100",
        "mac": "aa:bb:cc:dd:ee:ff",
        "mac_changes": 5,
        "message": "[TEST] ARP spoofing detected! IP 192.168.1.100 changed MAC addresses 5 times"
    }
    await broadcaster.push_alert(alert_data)
    return {"status": "ok", "alert": alert_data}
