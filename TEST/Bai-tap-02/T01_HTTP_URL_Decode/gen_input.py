"""Sinh input.pcap cho T01 — HTTP GET chứa percent-encoded URI.

10 frame phủ các trường hợp decode khác nhau (xem report.md).
"""
import os

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

# (mô tả, raw_path trên wire — percent-encoded)
FRAMES = [
    ("SQL injection: %27=' %20=space %3D==",
     "/search?q=%27%20OR%201%3D1"),
    ("'+' trong query → space, path giữ '+'",
     "/s+a?q=hello+world"),
    ("UTF-8 tiếng Việt percent-encoded",
     "/tim?q=ti%E1%BA%BFng%20Vi%E1%BB%87t"),
    ("XSS: encode < > ( ) /",
     "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    ("%2F = slash encoded trong path",
     "/user%2Fadmin%2Fprofile?role=admin"),
    ("%20 = space trong path",
     "/path%20with%20spaces/index.html"),
    ("query nhiều param: '+' + UTF-8 %XX",
     "/s?name=Nguy%E1%BB%85n+V%C4%83n+A&city=Ha+Noi"),
    ("URL encode cả URL (redirect target)",
     "/redir?url=https%3A%2F%2Fexample.com%2F%3Fa%3D1"),
    ("% không hợp lệ (%zz) — giữ nguyên, không crash",
     "/search?q=100%zz"),
    ("không có encoding — không cần decode",
     "/index.html"),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
for i, (desc, path) in enumerate(FRAMES):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
           IP(src="10.0.0.1", dst="10.0.0.2") /
           TCP(sport=40000, dport=80, flags="PA",
               seq=1 + i * 100, ack=1) /
           Raw(load=(f"GET {path} HTTP/1.1\r\n"
                     f"Host: example.com\r\n\r\n").encode()))
    pkt.time = 1700000000.0 + i      # timestamp cố định → tái tạo được
    writer.write(pkt)
writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({len(FRAMES)} frames)")
