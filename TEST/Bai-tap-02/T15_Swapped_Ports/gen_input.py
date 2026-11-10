"""Sinh input.pcap cho T15 — 2 flow cùng cặp IP, port đổi chỗ cho nhau."""
import os

from scapy.all import Ether, IP, UDP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

frames = [
    # flow A: 10.0.0.1:1000 ↔ 10.0.0.2:2000
    Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000) / Raw(b"A-req"),
    # flow B: 10.0.0.1:2000 ↔ 10.0.0.2:1000 (cùng IP, port đổi chỗ)
    Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=2000, dport=1000) / Raw(b"B-req"),
    # chiều ngược của flow A
    Ether(src=MAC2, dst=MAC1) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=2000, dport=1000) / Raw(b"A-resp"),
    # chiều ngược của flow B
    Ether(src=MAC2, dst=MAC1) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=1000, dport=2000) / Raw(b"B-resp"),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
