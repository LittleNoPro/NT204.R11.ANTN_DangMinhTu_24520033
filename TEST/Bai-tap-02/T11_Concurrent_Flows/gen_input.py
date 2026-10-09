"""Sinh input.pcap cho T11 — nhiều flow đồng thời, xen kẽ, khác port."""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

flows = [
    ("10.0.0.1", 40000, "10.0.0.2", 80),
    ("10.0.0.1", 40001, "10.0.0.2", 80),
    ("10.0.0.3", 50000, "10.0.0.2", 443),
]

frames = []
for i, (src, sport, dst, dport) in enumerate(flows):
    payload = f"GET /flow{i} HTTP/1.1\r\n\r\n".encode()
    req = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) / Raw(load=payload))
    resp = (Ether(src=MAC2, dst=MAC1) / IP(src=dst, dst=src) /
            TCP(sport=dport, dport=sport, flags="PA", seq=100, ack=len(payload) + 1) /
            Raw(load=b"HTTP/1.1 200 OK\r\n\r\nOK"))
    frames += [req, resp]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")