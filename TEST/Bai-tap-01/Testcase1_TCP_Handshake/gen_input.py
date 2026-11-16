"""Sinh input.pcap cho testcase 1 — TCP 3-way handshake SYN → SYN/ACK → ACK."""
import os

from scapy.all import Ether, IP, TCP, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
C_MAC, S_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
C_IP, S_IP, C_PORT, S_PORT = "192.168.1.10", "192.168.1.20", 51000, 80

frames = [
    Ether(src=C_MAC, dst=S_MAC) / IP(src=C_IP, dst=S_IP) /
    TCP(sport=C_PORT, dport=S_PORT, flags="S", seq=1000),
    Ether(src=S_MAC, dst=C_MAC) / IP(src=S_IP, dst=C_IP) /
    TCP(sport=S_PORT, dport=C_PORT, flags="SA", seq=5000, ack=1001),
    Ether(src=C_MAC, dst=S_MAC) / IP(src=C_IP, dst=S_IP) /
    TCP(sport=C_PORT, dport=S_PORT, flags="A", seq=1001, ack=5001),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
