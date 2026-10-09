"""Sinh input.pcap cho T03 — SMTP message MIME (Base64 / Quoted-Printable).

10 frame: 9 message DATA chứa CTE header + 1 command HELO (điều khiển thường).
"""
import base64
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

HDR = b"From: sender@example.com\r\nTo: receiver@example.com\r\nSubject: Test\r\nContent-Type: text/plain\r\n"

# Base64 dài wrap 76 ký tự/dòng theo chuẩn MIME RFC 2045
_LONG = ("Chào mừng bạn đến với hệ thống IDS thử nghiệm phát hiện tấn công "
         "qua email — hỗ trợ decode cả nội dung dài được wrap nhiều dòng.")
_LONG_B64 = "\r\n".join(
    base64.b64encode(_LONG.encode()).decode()[i:i + 76]
    for i in range(0, len(base64.b64encode(_LONG.encode()).decode()), 76))

# (mô tả, payload_bytes đầy đủ trên wire)
FRAMES = [
    ("Base64 ASCII đơn giản",
     HDR + b"Content-Transfer-Encoding: base64\r\n\r\n"
     + base64.b64encode(b"Hello World")),
    ("Base64 wrap 76 ký tự/dòng, tiếng Việt",
     HDR + b"Content-Transfer-Encoding: base64\r\n\r\n"
     + _LONG_B64.encode()),
    ("Quoted-printable: =48=65=6C=6C=6F",
     HDR + b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
     b"=48=65=6C=6C=6F=20IDS=21"),
    ("Quoted-printable soft break: '=' cuối dòng nối tiếp",
     HDR + b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
     b"=48=65=6C=6C=6F =\r\nWorld"),
    ("Quoted-printable trộn escape + UTF-8 literal",
     HDR + b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
     b"Ngon ng=C3=A3: " + "tiếng Việt".encode()),
    ("Base64 rác (!!!) → error, không crash",
     HDR + b"Content-Transfer-Encoding: base64\r\n\r\n"
     b"!!! not base64 !!!"),
    ("Base64 hợp lệ nhưng ra binary không phải UTF-8 → partial",
     HDR + b"Content-Transfer-Encoding: base64\r\n\r\n"
     + base64.b64encode(b"\x89PNG\r\n\x1a\nbinary-x")),
    ("CTE tên/value lẫn lộn hoa thường: CONTENT-TRANSFER-ENCODING: Base64",
     HDR + b"CONTENT-TRANSFER-ENCODING: Base64\r\n\r\n"
     + base64.b64encode(b"Mixed Case Header")),
    ("CTE không hỗ trợ: 8bit → giữ nguyên",
     HDR + b"Content-Transfer-Encoding: 8bit\r\n\r\n"
     + "thử 8bit body".encode()),
    ("Command HELO (không phải DATA) → không decode",
     b"HELO client.example.com\r\n"),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, (desc, payload) in enumerate(FRAMES):
    # client 10.0.0.1:40000 → server 10.0.0.2:25 (SMTP)
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
           IP(src="10.0.0.1", dst="10.0.0.2") /
           TCP(sport=40000, dport=25, flags="PA",
               seq=1 + i * 200, ack=1) /
           Raw(load=payload))
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(FRAMES)} frames)")
