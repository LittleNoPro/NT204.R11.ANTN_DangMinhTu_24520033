"""Sinh input.pcap cho T17 — chính sách skip theo cấu hình (skip_unknown, max_payload trong config.json)."""
import os

from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

def http_get(path, sport):
    payload = f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
    return (Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=sport, dport=80, flags="PA", seq=1, ack=1) / Raw(load=payload))

frames = [
    # 1. HTTP nhỏ, có "../" → hợp lệ, engine đánh giá và match sid 1000001
    http_get("/../etc", 40000),
    # 2. HTTP payload lớn (path dài) cũng chứa "../" → vượt max_payload → skip
    http_get("/../" + "A" * 300, 40001),
    # 3. UDP port lạ, application UNKNOWN → skip khi bật skip_unknown
    Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.3", dst="10.0.0.4") /
    UDP(sport=5000, dport=9999) / Raw(b"hello"),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
