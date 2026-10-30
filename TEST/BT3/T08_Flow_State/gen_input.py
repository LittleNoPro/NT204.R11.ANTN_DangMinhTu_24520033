"""Sinh input.pcap cho T08 — flow:to_server/to_client, established/not_established.

Phiên TCP: SYN mang payload (chưa established) → SYN/ACK → ACK → GET → response.
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


C, S = "10.0.0.1", "10.0.0.2"
req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
frames = [
    tcp(C, 40000, S, 80, "S", b"GET /early", seq=1000, ack=0),      # 1 HANDSHAKE
    tcp(S, 80, C, 40000, "SA", seq=5000, ack=1011),                 # 2
    tcp(C, 40000, S, 80, "A", seq=1011, ack=5001),                  # 3 ESTABLISHED
    tcp(C, 40000, S, 80, "PA", req, seq=1011, ack=5001),            # 4 to_server
    tcp(S, 80, C, 40000, "PA", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        seq=5001, ack=1011 + len(req)),                             # 5 to_client
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
