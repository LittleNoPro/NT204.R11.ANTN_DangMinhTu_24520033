"""Sinh input.pcap cho T05 — normalization: host/protocol/path khác format."""
import os

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, PcapWriter

HERE = os.path.dirname(os.path.abspath(__file__))

REQ = "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n\r\n"

CASES = [
    ("host hoa + trailing dot", REQ.format(path="/A", host="ExAmPlE.CoM.", ua="x")),
    ("host có port + hoa", REQ.format(path="/a/b", host="EXAMPLE.com:8080", ua="x")),
    ("host underscore + double dot", REQ.format(path="/x", host="bad_host..example.com", ua="x")),
    ("path double slash + dot segment", REQ.format(path="/api//v1/./users", host="example.com", ua="x")),
    ("path percent-encoded", REQ.format(path="/caf%C3%A9/menu", host="example.com", ua="x")),
    ("header name mixed case", REQ.format(path="/h", host="example.com", ua="MyAgent/1.0")),
]

writer = PcapWriter(os.path.join(HERE, "input.pcap"), sync=True)
i = 0
for desc, payload in CASES:
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
           IP(src="192.168.1.100", dst="93.184.216.34") /
           TCP(sport=40000, dport=80, flags="PA", seq=1 + i * 200, ack=1) /
           Raw(load=payload.encode()))
    pkt.time = 1700000000.0 + i
    writer.write(pkt)
    i += 1

# DNS query không dấu chấm cuối + hoa -> host normalization
dns = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
       IP(src="192.168.1.100", dst="8.8.8.8") /
       UDP(sport=50000, dport=53) /
       DNS(rd=1, qd=DNSQR(qname="WIKIPEDIA.ORG")))
dns.time = 1700000000.0 + i
writer.write(dns)
i += 1

# IPv6 + port ngoài range giả lập qua raw header
ip6 = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
       IPv6(src="2001:0DB8:0000:0000:0000:0000:0000:0001",
            dst="2001:0DB8:0000:0000:0000:0000:0000:0002") /
       TCP(sport=443, dport=50001, flags="PA", seq=1, ack=1) /
       Raw(load=b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n"))
ip6.time = 1700000000.0 + i
writer.write(ip6)
i += 1

writer.close()
print("wrote", os.path.join(HERE, "input.pcap"), f"({i} frames)")
