"""Sinh input.pcap cho T10 — offset/depth giới hạn vùng tìm.

5 frame đặt pattern ở trong/ngoài vùng [offset, offset+depth).
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
payloads = [
    b"GET /etc/passwd HTTP/1.1\r\n\r\n",          # GET@0, passwd@9
    b"POST /GET HTTP/1.1\r\n\r\n",                # GET@6 (ngoài depth 3)
    b"GET /aaaaaaaaaaaaaaaaaaaaa/passwd\r\n\r\n",  # passwd@27 (ngoài 4..24)
    b"secret token at the beginning",              # secret@0 (trước offset 30)
    b"x" * 30 + b"secret",                          # secret@30
]
frames = [tcp(C, 40000, S, 80, "PA", p) for p in payloads]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
