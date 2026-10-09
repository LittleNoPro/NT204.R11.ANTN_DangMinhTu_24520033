"""Sinh input.pcap cho T02 — HTTP response body chứa HTML entity.

10 frame phủ các loại entity khác nhau (xem report.md).
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

# (mô tả, raw body — HTML entity như trên wire)
FRAMES = [
    ("XSS: encode thẻ bằng entity",
     "&lt;script&gt;alert(document.cookie)&lt;/script&gt;"),
    ("Entity kép &amp;lt; — decode 1 lần",
     "x &amp;lt; y"),
    ("Decimal numeric &#60; &#62;",
     "&#60;b&#62;bold&#60;/b&#62;"),
    ("Hex numeric &#x3C; &#x3D; &#x3E;",
     "&#x3C;img onerror&#x3D;x&#x3E;"),
    ("Entity nháy &quot; và &#39;",
     "&quot;hello&#39;world&quot;"),
    ("&nbsp; → space không ngắt dòng",
     "a&nbsp;b"),
    ("Decimal numeric tiếng Việt",
     "Ti&#7871;ng Vi&#7879;t"),
    ("Text thuần — không entity",
     "Just plain text, no entity."),
    ("Entity lạ &xyz; — giữ nguyên, không crash",
     "tag &xyz; stays"),
    ("Mixed: tag thật giữ nguyên, chỉ entity decode",
     "<p>Value: &lt;script&gt;</p>"),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, (desc, body) in enumerate(FRAMES):
    body_bytes = body.encode()
    payload = (b"HTTP/1.1 200 OK\r\n"
               b"Content-Type: text/html\r\n"
               b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
               b"Connection: close\r\n\r\n" + body_bytes)
    # server 10.0.0.2:80 → client 10.0.0.1:40000 (response)
    pkt = (Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") /
           IP(src="10.0.0.2", dst="10.0.0.1") /
           TCP(sport=80, dport=40000, flags="PA",
               seq=1 + i * 100, ack=1) /
           Raw(load=payload))
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(FRAMES)} frames)")
