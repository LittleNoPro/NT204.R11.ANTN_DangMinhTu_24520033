"""Sinh input.pcap cho TC09 — lưu và đọc lại alert từ Alert Repository.

Ba alert với đủ kiểu giá trị (TCP/UDP, có/không có priority và classtype):
1. 10.0.0.5:52133 → 192.168.1.20:80  HTTP GET chứa "../"          (TCP, priority 1)
2. 10.0.0.7:5353  → 192.168.1.53:53  DNS query malware.example     (UDP, priority 2)
3. 10.0.0.6:40001 → 192.168.1.21:80  HTTP GET /login?user=' OR 1=1  (rule không có
   priority/classtype → các trường này là null khi lưu)
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


C, S = "10.0.0.5", "192.168.1.20"
req = b"GET /static/../../etc/passwd HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
frames = [
    tcp(C, 52133, S, 80, "S", seq=1000, ack=0),
    tcp(S, 80, C, 52133, "SA", seq=7000, ack=1001),
    tcp(C, 52133, S, 80, "A", seq=1001, ack=7001),
    tcp(C, 52133, S, 80, "PA", req, seq=1001, ack=7001),
    Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.7", dst="192.168.1.53") /
    UDP(sport=5353, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="malware.example")),
    tcp("10.0.0.6", 40001, "192.168.1.21", 80, "PA",
        b"GET /login?user='%20OR%201=1-- HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        seq=5001, ack=9001),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1763164800.0 + i      # 2025-11-15T00:00:00Z, timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
