"""Sinh input.pcap cho TC14 — kịch bản tấn công dùng bộ rule thật (rules/local.rules).

Ngày 2025-11-15 (UTC), mạng nội bộ 192.168.1.0/24:
  08:00:00–08:00:40  203.0.113.10 quét NULL + XMAS 5 cổng của 192.168.1.20
  08:05:00–08:05:20  203.0.113.10 → 192.168.1.20:80 (HTTP): traversal /etc/passwd,
                     SQL injection, XSS trên cùng một kết nối
  08:30:00, 08:30:30 198.51.100.7 → 192.168.1.21:8080 (HTTP): traversal hai lần
  09:10:00, 09:10:20, 09:12:00  192.168.1.50 hỏi DNS evil.xyz
  09:20:00           203.0.113.10 → 192.168.1.25:25 (SMTP): lệnh EXPN
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
BASE = 1763193600.0                  # 2025-11-15T08:00:00Z
ATTACKER, ATTACKER2, WEB, WEB2, MAIL = "203.0.113.10", "198.51.100.7", "192.168.1.20", "192.168.1.21", "192.168.1.25"


def tcp(src, sport, dst, dport, flags, data=b"", seq=1, ack=1):
    pkt = (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    return pkt / Raw(load=data) if data else pkt


def session(t, client, sport, server, dport, payloads, gap=10):
    """Handshake ở giây t rồi gửi từng payload, cách nhau `gap` giây."""
    frames = [(t, tcp(client, sport, server, dport, "S", seq=1000, ack=0)),
              (t, tcp(server, dport, client, sport, "SA", seq=7000, ack=1001)),
              (t, tcp(client, sport, server, dport, "A", seq=1001, ack=7001))]
    seq = 1001
    for i, data in enumerate(payloads):
        frames.append((t + i * gap, tcp(client, sport, server, dport, "PA", data, seq=seq, ack=7001)))
        seq += len(data)
    return frames


def http(path, host):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def dns(t, name):
    return (t, Ether(src=MAC1, dst=MAC2) / IP(src="192.168.1.50", dst="192.168.1.53") /
            UDP(sport=5353, dport=53) / DNS(id=0x4242, rd=1, qd=DNSQR(qname=name)))


frames = []
for i, port in enumerate((21, 22, 23, 25, 80)):                       # 08:00 quét cổng
    frames.append((i * 10, tcp(ATTACKER, 61000 + i, WEB, port, "", seq=0, ack=0)))
    frames.append((i * 10 + 1, tcp(ATTACKER, 62000 + i, WEB, port, "FPU", seq=0, ack=0)))
frames += session(300, ATTACKER, 52000, WEB, 80, [                     # 08:05 tấn công web
    http("/download?file=../../etc/passwd", "shop.example.com"),
    http("/login?user='%20OR%201=1--", "shop.example.com"),
    http("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "shop.example.com"),
])
frames += session(1800, ATTACKER2, 53000, WEB2, 8080, [                # 08:30 traversal x2
    http("/static/../../app.conf", "intranet.example.com"),
    http("/static/../../db.conf", "intranet.example.com"),
], gap=30)
frames += [dns(4200, "evil.xyz"), dns(4220, "evil.xyz"), dns(4320, "evil.xyz")]   # 09:10
frames += session(4800, ATTACKER, 54000, MAIL, 25, [b"EXPN root\r\n"])            # 09:20

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for second, pkt in sorted(frames, key=lambda item: item[0]):
    pkt.time = BASE + second         # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
