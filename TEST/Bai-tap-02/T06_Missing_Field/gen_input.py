"""Sinh input.pcap cho T06 — event thiếu field không bắt buộc."""
import os

from scapy.all import Ether, ARP, IP, ICMP, TCP, UDP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

# ARP: không IP, không port, không application
arp = Ether(src=MAC1, dst=MAC2) / ARP(psrc="192.168.1.10", pdst="192.168.1.1")

# ICMP: có IP, không port, không application content
icmp = (Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") /
        ICMP(type=8, code=0))

# TCP SYN rỗng: có port nhưng không payload, không application
syn = (Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.3", dst="10.0.0.4") /
       TCP(sport=51000, dport=443, flags="S", seq=1000))

# UDP rỗng (port không phải DNS)
udp_empty = (Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.5", dst="10.0.0.6") /
             UDP(sport=5000, dport=9999) / Raw(load=b""))

# Ethernet frame không IP (unknown ethertype)
weird = Ether(src=MAC1, dst=MAC2, type=0x88B5) / Raw(load=b"\x00\x01")

frames = [arp, icmp, syn, udp_empty, weird]
writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")