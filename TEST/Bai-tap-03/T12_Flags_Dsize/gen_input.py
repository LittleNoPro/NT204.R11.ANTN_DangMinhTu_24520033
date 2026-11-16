"""Sinh input.pcap cho T12 — TCP flags và dsize.

9 frame TCP với tổ hợp flag và độ dài payload khác nhau.
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
frames = [
    tcp(C, 40000, S, 8000, "S"),                    # 1 SYN
    tcp(S, 8000, C, 40000, "SA"),                   # 2 SYN/ACK
    tcp(C, 40000, S, 8000, "A"),                    # 3 ACK
    tcp(C, 40000, S, 8000, "PA", b"0123456789"),    # 4 PSH/ACK, 10 byte
    tcp(C, 40000, S, 8000, "PA", b"A" * 150),       # 5 PSH/ACK, 150 byte
    tcp(C, 40001, S, 8000, "F"),                    # 6 FIN (không ACK)
    tcp(C, 40002, S, 8000, "RA"),                   # 7 RST/ACK
    tcp(C, 40003, S, 8000, ""),                     # 8 NULL scan
    tcp(C, 40004, S, 8000, "FPU"),                  # 9 XMAS scan
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
