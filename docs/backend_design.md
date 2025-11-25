- ids_backend(Backend logic):
    - config.py: Loader and manager of configuration for project-- reads config.yaml and merge with defaults
    - dectectors: directory that will contain files that detect the icmp flood, arp spoofing, etc. 
        - icmp_flood.py: ICMP flood detection that utilizes sliding windows-- if the threshold value for number of ICMP packets within another threshold value for sliding window length in seconds is met, then trigger alert 
            - Detects for both ipv4 and ipv6-- sends the ip address, packet count, and window value to alert 
    - capture.py: captures the packets using scapy-- note(Andy-- ICMP flooding): im not using bpf just cause it isn't the most reliable in filtering packets: it will take up more cpu usage just cause it's not filtering only for certain packets but will turn it on when deployed in the wild
    - centralized_detector.py: base class for all specific detectors-- inherit from centralized_detector
    - alerting.py: implement alert_broadcaster which stores the alerts and statistics, manages WebSocket clients, and broadcasts updates to dashboard
    - api.py: defines FastAPI endpoints and websocket routes for dashboard; pulls from detectors using alert_broadcaster to show recent alerts and update live
    
## Detection Modules

### ARP Spoofing Detector
Detects Man-in-the-Middle (MITM) attacks through ARP spoofing by monitoring IP-to-MAC address mappings.

**How it Works:**
- Tracks all MAC addresses associated with each IP address on the network
- Uses a sliding time window to monitor recent MAC address changes
- Triggers alerts when the same IP is associated with multiple different MAC addresses within the threshold

**Attack Detection:**
In a normal network, one IP address maps to one consistent MAC address. During an ARP spoofing attack, an attacker sends fake ARP replies claiming their MAC address belongs to a legitimate IP (like a router). This detector identifies this behavior by:
1. Recording all IP-to-MAC mappings from ARP packets
2. Detecting when an IP suddenly has multiple different MAC addresses
3. Counting MAC changes within a configurable time window
4. Alerting when changes exceed the threshold (default: 3 changes in 10 seconds)

**Configuration** (`config.yaml`):
```yaml
window_seconds: 10                    # Time window for counting MAC changes
arp_mac_change_threshold: 3           # Number of MAC changes to trigger alert
```

**Files:**
- `ids_backend/arp_detector.py` - Main detector implementation
- `tools/simulate_arp_spoof.py` - Attack simulation tool for testing
- `test_arp_detector.py` - Live packet capture test runner
- `test_arp_unit.py` - Unit tests for detector logic

**Testing:**
```bash
# Run unit tests
python test_arp_unit.py

# Run live detection (Terminal 1)
sudo python test_arp_detector.py

# Simulate attack (Terminal 2)
sudo python tools/simulate_arp_spoof.py
```

**Alert Example:**
```
ARP spoofing detected! IP 192.168.1.100 has been associated with 3 different 
MAC addresses in 10 seconds. Current MAC: c3:03:14:5b:24:b0, 
All MACs seen: ['c3:03:14:5b:24:b0', '02:25:81:24:94:0a', 'ea:0f:b2:22:9c:38', 'a4:64:05:35:61:fb']
```

---
