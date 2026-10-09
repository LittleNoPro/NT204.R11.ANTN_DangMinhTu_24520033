"""Sinh input.pcap cho T08 — packet hai chiều cùng 5-tuple."""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, B = "10.0.0.1", "10.0.0.2"
REQ = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

frames = [
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) /
    TCP(sport=40000, dport=80, flags="PA", seq=1, ack=1) / Raw(load=REQ),
    Ether(src=MAC2, dst=MAC1) / IP(src=B, dst=A) /
    TCP(sport=80, dport=40000, flags="PA", seq=100, ack=len(REQ) + 1) / Raw(load=RESP),
    Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=B) /
    TCP(sport=40000, dport=80, flags="A", seq=len(REQ) + 1, ack=len(RESP) + 100),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")