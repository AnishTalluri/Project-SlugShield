<<<<<<< HEAD
import threading 
import time 
import uvicorn 
import asyncio 
=======
# run_backend.py

import threading
import time
import uvicorn
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)

from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.detectors.icmp_flood import icmp_counter_detector
<<<<<<< HEAD
from ids_backend import alerting
from ids_backend.api import app

#newly added
from ids_backend.ssh_detector import ssh_detector

# On separate thread, run FastAPI dashboard backend
def start_api():
    uvicorn.run(app, host = "127.0.0.1", port = 8080, log_level = "info")

def main():
    app_config = load_config_file()
    loop = asyncio.get_event_loop()
    alert_mngr = alerting.alert_broadcaster(loop)
    alerting.broadcaster = alert_mngr 
    icmp_detector = icmp_counter_detector(app_config, alert_mngr)
    live_packet_sniffer = PacketCapture(app_config)
    live_packet_sniffer.add_detection(icmp_detector.analyze_packet)
    
    #newly added
    live_packet_sniffer.add_detection(ssh_detector)
    
    # Start FastAPI in a background thread
    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()
    # Start capture in background thread
    thread = threading.Thread(target=live_packet_sniffer.start_sniff, daemon=True)
    thread.start()

    print("API: http://127.0.0.1:8080")
    print("Detector is running. Stop program from running with Ctrl+C.\n")
=======
from ids_backend.ssh_detector import ssh_detector
from ids_backend.alerting import broadcaster   # GLOBAL broadcaster
from ids_backend.api import router             # router only (NO app import)


# ============================================================
# Create FastAPI app (the only app)
# ============================================================

app = FastAPI(title="IDS API")

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add all routes from api.py
app.include_router(router)


# ============================================================
# Start API in background thread
# ============================================================

def start_api():
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")


# ============================================================
# Main IDS Logic
# ============================================================

def main():
    app_config = load_config_file()

    # Shared global broadcaster → already imported
    live_packet_sniffer = PacketCapture(app_config)

    # ICMP detector using the same broadcaster
    icmp_detector = icmp_counter_detector(app_config, broadcaster)
    live_packet_sniffer.add_detection(icmp_detector.analyze_packet)

    # SSH detector
    live_packet_sniffer.add_detection(ssh_detector)

    # Start API server
    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()

    # Start packet sniffer
    sniff_thread = threading.Thread(target=live_packet_sniffer.start_sniff, daemon=True)
    sniff_thread.start()

    print("\nBackend running!")
    print("Dashboard: http://127.0.0.1:8080")
    print("Sniffing interface:", app_config.interface)
    print("Press Ctrl+C to stop.\n")

>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
<<<<<<< HEAD
        print('Shutting down...\n')
        live_packet_sniffer.stop_sniff()

if __name__ == '__main__':
    main()
=======
        print("\nShutting down backend...")
        live_packet_sniffer.stop_sniff()


if __name__ == "__main__":
    main()
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
