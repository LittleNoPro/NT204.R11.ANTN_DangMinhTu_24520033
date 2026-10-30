"""Sinh input.pcap cho T06 — Indexer với ip, tcp, udp và any.

7 frame khác protocol/port; trace.jsonl ghi tập candidate rules của từng frame.
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


def udp(src, sport, dst, dport, data=b""):
    pkt = Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return pkt / Raw(load=data) if data else pkt


A, B, M = "10.0.0.1", "10.0.0.2", "10.0.0.5"
frames = [
    tcp(A, 40000, B, 80, "PA", b"GET / HTTP/1.1\r\n\r\n"),   # 1 TCP -> 80
    tcp(B, 80, A, 40000, "PA", b"HTTP/1.1 200 OK\r\n\r\n"),  # 2 TCP 80 ->
    tcp(A, 40002, B, 22, "S"),                                  # 3 TCP -> 22
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) / UDP(sport=51000, dport=53) /
    DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")),        # 4 UDP -> 53
    udp(A, 51001, B, 123, b"ntp"),                              # 5 UDP -> 123
    tcp(M, 25, A, 50000, "PA", b"220 mail ready\r\n"),          # 6 TCP 25 ->
    tcp(A, 40003, B, 1500, "S"),                                # 7 TCP -> 1500
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
