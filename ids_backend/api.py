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