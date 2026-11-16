"""Sinh input.pcap cho T02 — 1 phiên HTTP ngắn để chứng minh engine vẫn chạy
sau khi gặp rule lỗi: handshake → GET → response.
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
C, S = "10.0.0.1", "10.0.0.2"
CP, SP = 40000, 80
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def c2s(flags, seq, ack, data=b""):
    pkt = IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags=flags, seq=seq, ack=ack)
    return Ether(src=MAC1, dst=MAC2) / (pkt / Raw(load=data) if data else pkt)


def s2c(flags, seq, ack, data=b""):
    pkt = IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags=flags, seq=seq, ack=ack)
    return Ether(src=MAC1, dst=MAC2) / (pkt / Raw(load=data) if data else pkt)


req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
frames = [
    c2s("S", 1000, 0),
    s2c("SA", 5000, 1001),
    c2s("A", 1001, 5001),
    c2s("PA", 1001, 5001, req),
    s2c("PA", 5001, 1001 + len(req), resp),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
