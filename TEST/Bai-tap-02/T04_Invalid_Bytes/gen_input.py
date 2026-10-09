"""Sinh input.pcap cho T04 — payload không phải UTF-8 hợp lệ."""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

BAD = [
    ("lone continuation byte", b"\x80abc"),
    ("truncated 2-byte sequence", b"hello\xc3"),
    ("UTF-16 BOM", b"\xff\xfeh\x00i\x00"),
    ("overlong encoding", b"\xc0\xaf"),
    ("surrogate half", b"\xed\xa0\x80"),
    ("valid + invalid trộn", b"OK\xffEND"),
    ("binary ngẫu nhiên", bytes(range(0x00, 0x20)) + b"\x89\x90\xa0"),
    ("UTF-8 hợp lệ (không lỗi)", "tiếng Việt ok".encode()),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, (desc, payload) in enumerate(BAD):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
           IP(src="10.0.0.1", dst="10.0.0.2") /
           TCP(sport=40000, dport=8080, flags="PA",
               seq=1 + i * 100, ack=1) /
           Raw(load=payload))
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(BAD)} frames)")
