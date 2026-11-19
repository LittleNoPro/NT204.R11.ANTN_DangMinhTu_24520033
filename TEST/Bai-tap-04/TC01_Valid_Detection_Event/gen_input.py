"""Sinh input.pcap cho TC01 — Detection Event hợp lệ → Alert Object.

Ba tấn công khác nhau (khác SID, khác cặp IP) nên không bị gom nhóm:
1. 10.0.0.5 → 192.168.1.20:80  HTTP GET chứa "../"           (sid 4010001, priority 1)
2. 10.0.0.6 → 192.168.1.21:80  HTTP GET chứa "' OR 1=1"      (sid 4010002, priority 2)
3. 10.0.0.7 → 192.168.1.53:53  DNS query malware.example     (sid 4010003, priority 3)
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


def handshake_get(client, sport, server, path, host):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    return [
        tcp(client, sport, server, 80, "S", seq=1000, ack=0),
        tcp(server, 80, client, sport, "SA", seq=7000, ack=1001),
        tcp(client, sport, server, 80, "A", seq=1001, ack=7001),
        tcp(client, sport, server, 80, "PA", req, seq=1001, ack=7001),
    ]


frames = (
    handshake_get("10.0.0.5", 52133, "192.168.1.20", "/static/../../etc/passwd", "shop.example.com")
    + handshake_get("10.0.0.6", 40001, "192.168.1.21", "/login?user='%20OR%201=1--", "app.example.com")
    + [Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.7", dst="192.168.1.53") /
       UDP(sport=5353, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="malware.example"))]
)

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1763164800.0 + i      # 2025-11-15T00:00:00Z, timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
