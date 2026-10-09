"""Sinh input.pcap cho T14 — packet malformed/unsupported, không được crash."""
import os

from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))
MAC1, MAC2 = "02:00:00:00:00:01", "02:00:00:00:00:02"

# TCP header bị cắt cụt (chỉ 10 byte của 20)
trunc_tcp = Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.1", dst="10.0.0.2") / Raw(
    load=bytes.fromhex("9c4c0050000000004006"))

# IP version sai (nibble 15)
bad_ip = Ether(src=MAC1, dst=MAC2) / Raw(load=b"\xf0\x00\x00\x14" + b"JUNK" * 5)

# Ethernet type IPv4 nhưng payload không phải IP
bad_eth = Ether(src=MAC1, dst=MAC2, type=0x0800) / Raw(load=b"NOT-AN-IP-PACKET-AT-ALL-XXXXXX")

# IP total_len khai 1000 nhưng capture chỉ 60 byte
lie_len = Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.3", dst="10.0.0.4", len=1000) / Raw(
    load=b"short")

# UDP length = 0 (vượt chuẩn RFC 768)
udp_zero = Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.5", dst="10.0.0.6") / UDP(
    sport=1234, dport=53, len=0) / Raw(load=b"\x00\x01")

# TCP sport = 0 (trong khoảng hợp lệ nhưng vô lý)
tcp_port0 = Ether(src=MAC1, dst=MAC2) / IP(src="10.0.0.7", dst="10.0.0.8") / TCP(
    sport=0, dport=9999, flags="PA", seq=1, ack=1) / Raw(load=b"garbage")

frames = [trunc_tcp, bad_ip, bad_eth, lie_len, udp_zero, tcp_port0]
writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, pkt in enumerate(frames):
    pkt.time = 1700000000.0 + i
    try:
        writer.write(pkt)
    except Exception as error:
        print(f"skip frame {i}: {error}")
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(frames)} frames)")