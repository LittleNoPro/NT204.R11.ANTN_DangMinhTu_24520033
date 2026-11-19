"""Sinh input.pcap cho TC05 — lọc (suppress) theo SID.

Hai client cùng gửi GET /admin/config.php tới web server; mỗi request khớp 3 rule:
1. 10.0.0.5:52133   → 192.168.1.20:80  (máy quét nội bộ đã biết)
2. 172.16.0.9:40001 → 192.168.1.20:80
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


def handshake_get(client, sport, server, path, host):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    return [
        tcp(client, sport, server, 80, "S", seq=1000, ack=0),
        tcp(server, 80, client, sport, "SA", seq=7000, ack=1001),
        tcp(client, sport, server, 80, "A", seq=1001, ack=7001),
        tcp(client, sport, server, 80, "PA", req, seq=1001, ack=7001),
    ]


frames = (handshake_get("10.0.0.5", 52133, "192.168.1.20", "/admin/config.php", "shop.example.com")
          + handshake_get("172.16.0.9", 40001, "192.168.1.20", "/admin/config.php", "shop.example.com"))

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1763164800.0 + i      # 2025-11-15T00:00:00Z, timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
