"""
SSH Brute Force Attack Simulator

This script simulates an SSH brute force attack by sending TCP SYN packets
to port 22 from the same source IP.

Usage:
    sudo python tools/simulate_ssh_bruteforce.py

WARNING: Only use this on your own network for testing purposes!
"""

from scapy.all import IP, TCP, send
import time
import random

def simulate_ssh_bruteforce(target_ip='127.0.0.1', source_ip='192.168.1.50', num_attempts=15, delay=0.5):
    """
    Simulates SSH brute force by sending TCP SYN packets to port 22.
    
    Args:
        target_ip: The target IP to attack (default: localhost)
        source_ip: The fake source IP of the attacker
        num_attempts: Number of connection attempts
        delay: Delay in seconds between attempts
    """
    print(f"Starting SSH brute force simulation")
    print(f"Target: {target_ip}:22")
    print(f"Fake source: {source_ip}")
    print(f"Attempts: {num_attempts}")
    print(f"Delay: {delay} seconds\n")
    
    print("Sending SSH connection attempts (Ctrl+C to stop)...\n")
    
    try:
        for i in range(num_attempts):
            # Create TCP SYN packet to port 22 (SSH)
            # SYN flag = 0x02
            packet = IP(src=source_ip, dst=target_ip)/TCP(dport=22, flags='S', sport=random.randint(1024, 65535))
            
            # Send the packet
            send(packet, verbose=False)
            
            print(f"Attempt {i+1}: TCP SYN from {source_ip} to {target_ip}:22")
            time.sleep(delay)
                
    except KeyboardInterrupt:
        print(f"\n\nStopped. Sent {i+1} SSH connection attempts.")

if __name__ == '__main__':
    print("=" * 60)
    print("SSH Brute Force Simulator")
    print("=" * 60)
    print("\nThis will simulate an SSH brute force attack.")
    print("Make sure your IDS is running to detect it!\n")
    
    # You can customize these values
    # Use your actual network interface IP instead of loopback
    # Run 'ip addr' or 'hostname -I' to find your IP
    TARGET_IP = '172.26.68.89'   # Replace with your actual IP (from 'hostname -I')
    SOURCE_IP = '192.168.1.50'   # Fake attacker IP
    NUM_ATTEMPTS = 15            # Number of attempts
    DELAY = 0.5                  # Seconds between attempts
    
    print(f"NOTE: If no alerts appear, replace TARGET_IP with your actual IP")
    print(f"      Run 'hostname -I' to find your IP address\n")
    
    simulate_ssh_bruteforce(TARGET_IP, SOURCE_IP, NUM_ATTEMPTS, DELAY)
    
    print("\n" + "=" * 60)
    print("Simulation complete!")
    print("=" * 60)
