"""Sinh input.pcap cho T10 — DNS UDP query/response hai chiều."""
import os

from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
A, S = "192.168.1.10", "8.8.8.8"

query = (Ether(src=MAC1, dst=MAC2) / IP(src=A, dst=S) /
         UDP(sport=51000, dport=53) /
         DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")))
resp = (Ether(src=MAC2, dst=MAC1) / IP(src=S, dst=A) /
        UDP(sport=53, dport=51000) /
        DNS(id=0x1234, qr=1, aa=1, rd=1, ra=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")))

frames = [query, resp]
writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")