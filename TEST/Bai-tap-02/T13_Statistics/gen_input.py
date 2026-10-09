"""Sinh input.pcap cho T13 — thống kê: nhiều packet hai chiều, đủ counter."""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, B = "10.0.0.1", "10.0.0.2"

# payload cố định để tính byte_count chính xác
FWD100 = b"F" * 100
BWD50 = b"B" * 50

frames = [
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S", seq=1),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="SA", seq=500, ack=2),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="A", seq=2, ack=501),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="PA", seq=2, ack=501) / Raw(load=FWD100),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="PA", seq=501, ack=102) / Raw(load=BWD50),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="PA", seq=102, ack=551) / Raw(load=FWD100),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="PA", seq=551, ack=202) / Raw(load=BWD50),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="FA", seq=202, ack=601),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="FA", seq=601, ack=203),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="A", seq=203, ack=602),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i * 2        # 2s mỗi packet → duration dễ kiểm
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")