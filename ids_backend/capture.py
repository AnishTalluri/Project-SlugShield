import socket
import threading
import struct
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.all import Ether


class PacketCapture:

    def __init__(self, app_config):
        self.interface = app_config.interface
        self.running = False
        self.detectors = []

    def add_detection(self, callback):
        self.detectors.append(callback)

    def start_sniff(self):
        self.running = True

        # -------- RAW SOCKET (macOS-compatible) ----------
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((self.interface, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(0x80000069, 1)   # SIOCGIFFLAGS
        sock.ioctl(0x40000069, 1)   # SIOCSIFFLAGS = PROMISC

        print(f"[RAW SNIFFER] Listening on {self.interface}")

        while self.running:
            packet = sock.recvfrom(65565)[0]

            try:
                # Parse IP packet
                ip_pkt = IP(packet)

                # Run detectors
                for det in self.detectors:
                    det(ip_pkt)

            except Exception:
                continue

    def stop_sniff(self):
        self.running = False
