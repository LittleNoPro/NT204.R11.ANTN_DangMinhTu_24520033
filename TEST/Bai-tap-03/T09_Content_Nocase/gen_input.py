"""Sinh input.pcap cho T09 — content có/không có nocase.

4 frame HTTP: /admin, /ADMIN, /AdMiN, /user.
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
paths = [b"/admin", b"/ADMIN", b"/AdMiN", b"/user"]
frames = [tcp(C, 40000, S, 80, "PA", b"GET " + p + b" HTTP/1.1\r\nHost: example.com\r\n\r\n")
          for p in paths]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
