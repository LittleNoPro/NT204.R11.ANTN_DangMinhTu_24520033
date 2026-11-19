"""Sinh input.pcap cho TC02 — ánh xạ priority → severity.

Một phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80; request cuối khớp cùng lúc 7 rule
có priority khác nhau (1, 2, 3, 4, 5, 7 và không khai báo priority).
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


C, S = "10.0.0.5", "192.168.1.20"
req = b"GET /admin/config.php HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
frames = [
    tcp(C, 52133, S, 80, "S", seq=1000, ack=0),
    tcp(S, 80, C, 52133, "SA", seq=7000, ack=1001),
    tcp(C, 52133, S, 80, "A", seq=1001, ack=7001),
    tcp(C, 52133, S, 80, "PA", req, seq=1001, ack=7001),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1763164800.0 + i      # 2025-11-15T00:00:00Z, timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
