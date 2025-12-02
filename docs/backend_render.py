from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Pull in ALL of our real API routes
# (alerts, stats, thresholds, email, websocket, test endpoints, etc.)
from ids_backend.api import router


# ============================================================
# FastAPI App Setup
# ============================================================
# This is the stripped-down version of the backend that runs on Render.
# No sniffers, no threads — just the API.
app = FastAPI(
    title="SlugShield IDS API (Render Version)",
    description="API-only version for the deployed dashboard.",
    version="1.0.0"
)


# ============================================================
# CORS (so our Vercel frontend can talk to this)
# ============================================================
# Vercel uses different domains for previews/production,
# so easiest thing is just allowing everything for now.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Works with local dev + Vercel
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Include Routes
# ============================================================
# All of the actual logic lives in ids_backend/api.py.
# This just mounts it so the endpoints still work on Render.
app.include_router(router)


# ============================================================
# Basic Root Endpoint
# ============================================================
# This is mainly for testing and for Render's "health check".
@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "SlugShield API running (Render version)",
        "note": "This version does NOT sniff packets — API only.",
        "docs": "/docs"
    }