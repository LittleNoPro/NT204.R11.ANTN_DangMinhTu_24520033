"""Sinh input.pcap cho T12 — idle timeout: chênh timestamp vượt timeout.

Chạy với --udp-timeout 5 để 10s chênh nhau vượt timeout.
"""
import os

from scapy.all import Ether, IP, UDP, DNS, DNSQR, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, S = "192.168.1.10", "8.8.8.8"

q1 = (Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=S) /
      UDP(sport=51000, dport=53) /
      DNS(id=1, rd=1, qd=DNSQR(qname="first.example.com")))
q2 = (Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=S) /
      UDP(sport=51000, dport=53) /
      DNS(id=2, rd=1, qd=DNSQR(qname="second.example.com")))

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
q1.time = 1700000000.0
writer.write(q1)
q2.time = 1700000010.0          # 10s > udp-timeout 5 → flow 1 hết hạn
writer.write(q2)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), "(2 frames, gap 10s)")