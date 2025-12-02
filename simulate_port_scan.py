from scapy.all import IP, TCP, send
target = "127.0.0.1"
for port in range(1, 1001):
    send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=False)
    if port % 100 == 0:
        print(f"Scanned {port} ports...")
print("Complete!")
