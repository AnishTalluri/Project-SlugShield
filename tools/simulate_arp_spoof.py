import time
import requests

BASE_URL = "http://127.0.0.1:8080/api/test"

def send(endpoint):
    try:
        requests.post(f"{BASE_URL}/{endpoint}", timeout=2)
    except Exception as e:
        print(f"[ERROR] {e}")


def baseline():
    print("\n[ARP BASELINE] Normal ARP activity...")
    for i in range(8):
        send("arp_baseline")  # value = 1
        print(f"  Baseline #{i+1}")
        time.sleep(0.3)


def arp_attack():
    print("\n[ARP SPOOFING ATTACK] Simulating ARP spoofing...")
    for i in range(12):
        send("arp_stat")    # pushes value = 8
        if i % 3 == 0:
            send("arp_alert")  # triggers alert
        print(f"  Attack #{i+1}")
        time.sleep(0.2)


def back_to_normal():
    print("\n[ARP BASELINE] Returning to normal traffic...")
    for i in range(8):
        send("arp_baseline")
        print(f"  Baseline #{i+1}")
        time.sleep(0.3)


if __name__ == "__main__":
    print("=== ARP Spoofing Detection Simulation ===")
    baseline()
    arp_attack()
    back_to_normal()
    print("\n>>> ARP Spoofing Simulation Complete! Check Dashboard + Alerts.\n")
