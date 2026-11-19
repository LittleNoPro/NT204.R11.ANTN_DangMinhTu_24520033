"""Sinh input.pcap cho TC08 — event ngoài cửa sổ tạo alert/nhóm mới.

Một phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80; client gửi 6 request chứa "../" ở
các giây 3, 30, 63, 64, 100, 200 (tính từ 2025-11-15T00:00:00Z). Với window 60 giây:
- 3, 30, 63  → nhóm 1 (63 − 3 = 60: đúng biên, vẫn trong cửa sổ)
- 64, 100    → nhóm 2 (64 − 3 = 61 > 60)
- 200        → nhóm 3 (200 − 64 = 136 > 60)
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
BASE = 1763164800.0                  # 2025-11-15T00:00:00Z


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


C, S = "10.0.0.5", "192.168.1.20"
frames = [
    (0, tcp(C, 52133, S, 80, "S", seq=1000, ack=0)),
    (1, tcp(S, 80, C, 52133, "SA", seq=7000, ack=1001)),
    (2, tcp(C, 52133, S, 80, "A", seq=1001, ack=7001)),
]
seq = 1001
for second, page in ((3, "a"), (30, "b"), (63, "c"), (64, "d"), (100, "e"), (200, "f")):
    req = f"GET /static/../{page}.cfg HTTP/1.1\r\nHost: shop.example.com\r\n\r\n".encode()
    frames.append((second, tcp(C, 52133, S, 80, "PA", req, seq=seq, ack=7001)))
    seq += len(req)

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for second, pkt in frames:
    pkt.time = BASE + second         # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
