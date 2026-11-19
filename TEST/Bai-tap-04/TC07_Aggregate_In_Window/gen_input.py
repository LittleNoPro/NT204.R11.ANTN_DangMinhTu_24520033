"""Sinh input.pcap cho TC07 — event lặp trong cửa sổ được gom nhóm.

Một phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80; client gửi 5 request chứa "../" ở
các giây 3, 13, 23, 33, 45 (tính từ 2025-11-15T00:00:00Z). Khoảng 3 → 45 là 42 giây,
nằm trong aggregation window 60 giây.
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
for second, page in ((3, "a"), (13, "b"), (23, "c"), (33, "d"), (45, "e")):
    req = f"GET /static/../{page}.cfg HTTP/1.1\r\nHost: shop.example.com\r\n\r\n".encode()
    frames.append((second, tcp(C, 52133, S, 80, "PA", req, seq=seq, ack=7001)))
    seq += len(req)

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for second, pkt in frames:
    pkt.time = BASE + second         # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
