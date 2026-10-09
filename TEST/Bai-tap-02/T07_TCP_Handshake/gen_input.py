"""Sinh input.pcap cho T07 — TCP handshake SYN → SYN/ACK → ACK."""
import os

from scapy.all import Ether, IP, TCP, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, B = "10.0.0.1", "10.0.0.2"

frames = [
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) /
    TCP(sport=40000, dport=80, flags="S", seq=1000),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) /
    TCP(sport=80, dport=40000, flags="SA", seq=2000, ack=1001),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) /
    TCP(sport=40000, dport=80, flags="A", seq=1001, ack=2001),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")