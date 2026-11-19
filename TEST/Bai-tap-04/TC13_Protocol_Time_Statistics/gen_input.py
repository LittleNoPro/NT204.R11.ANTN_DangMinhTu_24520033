"""Sinh input.pcap cho TC13 — thống kê theo protocol và theo thời gian.

8 tấn công trong 3 giờ ngày 2025-11-15 (UTC), mỗi cái một packet riêng:
  00:05  HTTP  10.0.0.5  → 192.168.1.20:80   GET chứa "../"
  00:20  HTTP  10.0.0.5  → 192.168.1.20:80   GET chứa "../"
  00:30  DNS   10.0.0.7  → 192.168.1.53:53   query malware.example
  01:10  HTTP  10.0.0.6  → 192.168.1.20:80   GET chứa "../"
  01:15  SMTP  10.0.0.8  → 192.168.1.25:25   thư chứa chuỗi EICAR
  01:40  DNS   10.0.0.7  → 192.168.1.53:53   query malware.example
  02:15  DNS   10.0.0.9  → 192.168.1.53:53   query malware.example
  02:50  TCP   10.0.0.10 → 192.168.1.30:4444 payload "cmd.exe" (không có protocol ứng dụng)
"""
import os

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
BASE = 1763164800.0                  # 2025-11-15T00:00:00Z


def tcp_data(src, sport, dst, dport, data):
    return (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=7001) / Raw(load=data))


def dns_query(src, dst, name):
    return (Ether(src=MAC1, dst=MAC2) / IP(src=src, dst=dst) /
            UDP(sport=5353, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname=name)))


def http_get(src, sport, path):
    return tcp_data(src, sport, "192.168.1.20", 80,
                    f"GET {path} HTTP/1.1\r\nHost: shop.example.com\r\n\r\n".encode())


frames = [  # (phút từ 00:00, packet)
    (5, http_get("10.0.0.5", 52133, "/static/../etc/passwd")),
    (20, http_get("10.0.0.5", 52134, "/static/../etc/shadow")),
    (30, dns_query("10.0.0.7", "192.168.1.53", "malware.example")),
    (70, http_get("10.0.0.6", 40001, "/../../boot.ini")),
    (75, tcp_data("10.0.0.8", 41000, "192.168.1.25", 25,
                  b"DATA\r\nSubject: invoice\r\n\r\nX5O!P%@AP EICAR-STANDARD-ANTIVIRUS-TEST-FILE\r\n.\r\n")),
    (100, dns_query("10.0.0.7", "192.168.1.53", "malware.example")),
    (135, dns_query("10.0.0.9", "192.168.1.53", "malware.example")),
    (170, tcp_data("10.0.0.10", 50000, "192.168.1.30", 4444, b"cmd.exe /c whoami\n")),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for minute, pkt in frames:
    pkt.time = BASE + minute * 60    # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")
