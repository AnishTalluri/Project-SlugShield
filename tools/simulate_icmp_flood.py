import sys
import os
import time
from scapy.all import IP, ICMP, send

if len(sys.argv) < 2:
    print('Program should at least have target_ip_address')
target = sys.argv[1]
if len(sys.argv) > 2:
    try:
        count = int(sys.argv[2])
    except ValueError:
        print('Count should be integer')
        sys.exit(1)
else:
    count = 1000

# Build icmp packet to send 
packet = IP(dst = target)/ICMP()
print(f'Sending {count} ICMP requests to {target}\n')
for i in range(count):
    send(packet, verbose=False)
    time.sleep(0.01)
print('Finished sending')