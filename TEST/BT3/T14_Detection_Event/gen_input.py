"""Sinh input.pcap cho T14 — Detection Event đầy đủ trường.

Phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80 (ví dụ trong đề): handshake → GET chứa "../".
"""
import os

from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


def udp(src, sport, dst, dport, data=b""):
    pkt = Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return pkt / Raw(load=data) if data else pkt


C, S = "10.0.0.5", "192.168.1.20"
req = b"GET /static/../../etc/passwd HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
frames = [
    tcp(C, 52133, S, 80, "S", seq=1000, ack=0),
    tcp(S, 80, C, 52133, "SA", seq=7000, ack=1001),
    tcp(C, 52133, S, 80, "A", seq=1001, ack=7001),
    tcp(C, 52133, S, 80, "PA", req, seq=1001, ack=7001),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
