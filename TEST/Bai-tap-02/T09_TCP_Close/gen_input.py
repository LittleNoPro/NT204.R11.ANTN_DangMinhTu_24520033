"""Sinh input.pcap cho T09 — TCP close: FIN cả hai chiều và RST."""
import os

from scapy.all import Ether, IP, TCP, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, B, C = "10.0.0.1", "10.0.0.2", "10.0.0.3"

# flow 1: handshake → FIN/ACK cả hai chiều → CLOSED
flow1 = [
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S", seq=1),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="SA", seq=100, ack=2),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="A", seq=2, ack=101),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="FA", seq=2, ack=101),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="FA", seq=101, ack=3),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="A", seq=3, ack=102),
]
# flow 2: handshake → RST → RESET
flow2 = [
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=C) / TCP(sport=41000, dport=443, flags="S", seq=1),
    Ether(src=MAC2, dst=MAC1) / IP(src=C, dst=A) / TCP(sport=443, dport=41000, flags="SA", seq=500, ack=2),
    Ether(src=MAC2, dst=MAC1) / IP(src=C, dst=A) / TCP(sport=443, dport=41000, flags="R", seq=501, ack=2),
]

frames = flow1 + flow2
writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")