import time
import requests

BASE_URL = "http://127.0.0.1:8080/api/test"

def send(endpoint):
    try:
        requests.post(f"{BASE_URL}/{endpoint}", timeout=2)
    except Exception as e:
        print(f"[ERROR] {e}")


def baseline():
    print("\n[ICMP BASELINE] Normal ping traffic (1 packet/sec)...")
    for i in range(10):
        send("icmp_baseline")
        print(f"  Baseline #{i+1}")
        time.sleep(1)


def icmp_flood():
    print("\n[ICMP FLOOD] Simulating ICMP flood attack (600 packets)...")
    # Send 600 packets as fast as possible
    for _ in range(600):
        send("icmp_alert")
    print("Attack burst sent (600 packets)")
    time.sleep(1)


def back_to_normal():
    print("\n[ICMP BASELINE] Returning to normal ping traffic...")
    for i in range(10):
        send("icmp_baseline")
        print(f"  Baseline #{i+1}")
        time.sleep(1)


if __name__ == "__main__":
    print("=== ICMP Flood Detection Simulation ===")
    #baseline()
    icmp_flood()
    #back_to_normal()
    print("\n>>> ICMP Flood Simulation Complete! Check Dashboard + Alerts.\n")