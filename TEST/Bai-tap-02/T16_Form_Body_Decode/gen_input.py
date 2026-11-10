"""Sinh input.pcap cho T16 — HTTP POST body application/x-www-form-urlencoded."""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

# (content-type, body trên wire)
BODIES = [
    ("application/x-www-form-urlencoded", "user=admin%27%20OR%201%3D1&pass=x"),
    ("application/x-www-form-urlencoded; charset=UTF-8", "name=Nguy%E1%BB%85n+V%C4%83n+A&city=Ha+Noi"),
    ("application/json", '{"q": "%27%20OR%201%3D1"}'),
    ("application/x-www-form-urlencoded", "user=admin&pass=secret"),
]

frames = []
for i, (ctype, body) in enumerate(BODIES):
    data = body.encode()
    payload = (f"POST /login HTTP/1.1\r\nHost: example.com\r\n"
               f"Content-Type: {ctype}\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
    frames.append(Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") /
                  TCP(sport=40000 + i, dport=80, flags="PA", seq=1, ack=1) / Raw(load=payload))

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
