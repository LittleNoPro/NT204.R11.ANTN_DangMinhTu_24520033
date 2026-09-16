#!/usr/bin/env python3
"""
test.py — Công cụ trích xuất packet từ file pcap lớn theo loại protocol,
để bạn tự lấy đúng những gói tin cần thiết cho từng test case.

Cách dùng (luôn chạy bằng python của venv):
    .venv/bin/python test.py --list
    .venv/bin/python test.py --type tcp --max 10
    .venv/bin/python test.py --type tcp --flags S,SA,A --max 3
    .venv/bin/python test.py --type http --contains "GET /"
    .venv/bin/python test.py --type smtp,dns --max 5
    .venv/bin/python test.py --type dns --output TEST/dns.pcap

--type chấp nhận nhiều loại cách nhau bằng dấu phẩy (toán tử OR: lấy packet
thuộc BẤT KỲ loại nào được liệt kê).

Muốn thêm loại protocol mới: chỉ cần định nghĩa 1 hàm kiểu
    def is_xxx(pkt): ...  -> True/False
rồi thêm 1 dòng vào từ điển MATCHERS bên dưới.
"""
import argparse
import logging
import sys

# Giảm nhiễu (vd: warning TLS do thiếu cryptography module)
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import (ARP, BOOTP, DHCP, DNS, ICMP, IP, IPv6, PcapReader,
                       PcapWriter, Raw, TCP, UDP)

# --- TLS: import an toàn, có thể thiếu ở vài bản scapy ---------------------
try:
    from scapy.layers.tls.record import TLS
    HAS_TLS = True
except Exception:
    TLS = None
    HAS_TLS = False

# ===========================================================================
# CÁC BỘ LỌC THEO LOẠI PROTOCOL
# ===========================================================================
HTTP_PORTS = (80, 8000, 8080, 8888)
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
SMTP_PORTS = (25, 465, 587)
SMTP_CMDS = (b"HELO ", b"EHLO ", b"MAIL FROM", b"RCPT TO", b"DATA",
             b"QUIT", b"NOOP", b"RSET", b"VRFY", b"EXPN")
FTP_PORTS = (20, 21)
FTP_CMDS = (b"USER ", b"PASS ", b"ACCT ", b"RETR ", b"STOR ", b"LIST",
            b"NLST", b"PWD", b"CWD ", b"QUIT", b"PORT ", b"PASV", b"TYPE ",
            b"SYST", b"HELP", b"NOOP", b"DELE ", b"MKD ", b"RMD ", b"RNFR ",
            b"RNTO ", b"ABOR", b"REST ", b"ALLO", b"SITE ", b"STAT")


def _raw_load(pkt):
    """Payload bytes của packet, None nếu không có."""
    if Raw in pkt:
        return bytes(pkt[Raw].load)
    return None


def _starts_3digit_response(load):
    """True nếu payload là phản hồi dạng '220 OK...' (mã 3 chữ số + space)."""
    return (len(load) >= 4 and load[:3].isdigit()
            and load[3] in (0x20, 0x2D))  # ' ' hoặc '-' (multi-line)


def is_all(pkt):
    return True


def is_tcp(pkt):
    return TCP in pkt


def is_udp(pkt):
    return UDP in pkt


def is_icmp(pkt):
    return ICMP in pkt


def is_igmp(pkt):
    # Scapy 2.7 không có lớp IGMP riêng — dùng IP protocol number 2.
    return IP in pkt and pkt[IP].proto == 2


def is_arp(pkt):
    return ARP in pkt


def is_ipv6(pkt):
    return IPv6 in pkt


def is_dhcp(pkt):
    return BOOTP in pkt or DHCP in pkt


def is_dns(pkt):
    if DNS in pkt:
        return True
    if UDP in pkt:
        u = pkt[UDP]
        return u.sport == 53 or u.dport == 53
    return False


def is_http(pkt):
    if TCP in pkt:
        t = pkt[TCP]
        if t.sport in HTTP_PORTS or t.dport in HTTP_PORTS:
            return True
        load = _raw_load(pkt)
        if load:
            if load.startswith(HTTP_METHODS):
                return True
            if load.startswith((b"HTTP/1.", b"HTTP/2 ")):
                return True
    return False


def is_smtp(pkt):
    if TCP in pkt:
        t = pkt[TCP]
        if t.sport in SMTP_PORTS or t.dport in SMTP_PORTS:
            return True
        load = _raw_load(pkt)
        if load:
            up = load.upper()
            if up.startswith(SMTP_CMDS):
                return True
            if _starts_3digit_response(load):
                return True
    return False


def is_ftp(pkt):
    if TCP in pkt:
        t = pkt[TCP]
        if t.sport in FTP_PORTS or t.dport in FTP_PORTS:
            return True
        load = _raw_load(pkt)
        if load:
            up = load.upper()
            if up.startswith(FTP_CMDS):
                return True
            if _starts_3digit_response(load):
                return True
    return False


def is_ssh(pkt):
    if TCP in pkt:
        t = pkt[TCP]
        if t.sport == 22 or t.dport == 22:
            return True
        load = _raw_load(pkt)
        if load and load.startswith(b"SSH-"):
            return True
    return False


def is_telnet(pkt):
    if TCP in pkt:
        t = pkt[TCP]
        return t.sport == 23 or t.dport == 23
    return False


def is_tls(pkt):
    if not HAS_TLS:
        return False
    if TCP in pkt:
        load = _raw_load(pkt)
        # bản thân lớp TLS của scapy sẽ tự nhận diện nếu có
        if TLS in pkt:
            return True
        # heuristic: record TLS 0x16 (handshake) / 0x17 (app data) + version 0x0301-0x0304
        if load and len(load) >= 5:
            if load[0] in (0x14, 0x15, 0x16, 0x17) and load[1:3] in (
                    b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"):
                return True
    return False


# Tên loại -> (mô tả, hàm lọc). Thêm loại mới bằng cách thêm dòng vào đây.
MATCHERS = {
    "all":    ("mọi packet", is_all),
    "tcp":    ("TCP (mọi cờ)", is_tcp),
    "udp":    ("UDP", is_udp),
    "icmp":   ("ICMP", is_icmp),
    "igmp":   ("IGMP", is_igmp),
    "arp":    ("ARP", is_arp),
    "ipv6":   ("IPv6", is_ipv6),
    "dhcp":   ("DHCP/BOOTP", is_dhcp),
    "dns":    ("DNS (lớp DNS hoặc port 53)", is_dns),
    "http":   ("HTTP (port 80/8080/8000/8888 hoặc payload GET/POST/HTTP/)",
               is_http),
    "smtp":   ("SMTP (port 25/465/587 hoặc payload HELO/MAIL FROM/response)",
               is_smtp),
    "ftp":    ("FTP (port 20/21 hoặc payload FTP/response)", is_ftp),
    "ssh":    ("SSH (port 22 hoặc banner SSH-)", is_ssh),
    "telnet": ("Telnet (port 23)", is_telnet),
    "tls":    ("TLS/SSL (lớp TLS hoặc record header 0x16/0x17)", is_tls),
}


def _packet_has_port(pkt, ports):
    if TCP in pkt:
        t = pkt[TCP]
        return t.sport in ports or t.dport in ports
    if UDP in pkt:
        u = pkt[UDP]
        return u.sport in ports or u.dport in ports
    return False


def _packet_has_flags(pkt, flags):
    return TCP in pkt and str(pkt[TCP].flags).upper() in flags


def _packet_contains(pkt, needle, case_insensitive):
    load = _raw_load(pkt)
    if load is None:
        return False
    if case_insensitive:
        return needle.lower() in load.lower()
    return needle in load


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(
        description="Trích xuất packet từ pcap lớn theo loại protocol.")
    ap.add_argument("--source", default="ultimate_wireshark_protocols_pcap_220213.pcap",
                    help="File pcap nguồn (mặc định: pcap trong thư mục)")
    ap.add_argument("--type", help="Loại cần lấy, cách nhau bởi dấu phẩy: "
                                   + ", ".join(MATCHERS.keys()))
    ap.add_argument("--max", type=int, default=10,
                    help="Số packet tối đa cần lấy (0 = quét hết file)")
    ap.add_argument("--output", default="extracted.pcap",
                    help="File pcap đầu ra")
    ap.add_argument("--port", help="Chỉ lấy packet có src/dst port thuộc danh sách, "
                                   "vd: --port 80,443")
    ap.add_argument("--flags", help="Chỉ lấy TCP packet có đúng các cờ này, "
                                    "vd: --flags S,SA,A")
    ap.add_argument("--contains", help="Chỉ lấy packet có chuỗi này trong payload, "
                                       "vd: --contains 'GET /'")
    ap.add_argument("--case-insensitive", action="store_true",
                    help="So khớp --contains không phân biệt hoa thường")
    ap.add_argument("--list", action="store_true",
                    help="Liệt kê các loại protocol hỗ trợ rồi thoát")
    ap.add_argument("--quiet", action="store_true", help="Không in tiến trình")

    args = ap.parse_args()

    if args.list:
        print("Các loại protocol hỗ trợ:")
        for name, (desc, _fn) in MATCHERS.items():
            print(f"  {name:<8} {desc}")
        return

    if not args.type:
        ap.error("Bắt buộc có --type (hoặc dùng --list để xem danh sách)")

    types = [t.strip().lower() for t in args.type.split(",")]
    unknown = [t for t in types if t not in MATCHERS]
    if unknown:
        ap.error(f"Loại không hợp lệ: {unknown}. Chạy --list để xem danh sách.")

    ports = set(int(x) for x in args.port.split(",")) if args.port else set()
    flags = {f.strip().upper() for f in args.flags.split(",")} if args.flags else set()
    needle = args.contains.encode() if args.contains else None

    scanned = written = 0
    hits = {t: 0 for t in types}

    with PcapReader(args.source) as reader, PcapWriter(args.output, append=False) as writer:
        for pkt in reader:
            scanned += 1
            if not args.quiet and scanned % 50000 == 0:
                print(f"  ...đã quét {scanned} packet, lấy được {written}", file=sys.stderr)

            # 1) khớp loại (OR)
            matched_type = None
            for t in types:
                if MATCHERS[t][1](pkt):
                    matched_type = t
                    break
            if matched_type is None:
                continue

            # 2) bộ lọc phụ (AND) — nếu khai báo thì phải khớp tất cả
            if ports and not _packet_has_port(pkt, ports):
                continue
            if flags and not _packet_has_flags(pkt, flags):
                continue
            if needle is not None and not _packet_contains(pkt, needle, args.case_insensitive):
                continue

            writer.write(pkt)
            hits[matched_type] += 1
            written += 1
            if args.max and written >= args.max:
                break

    print(f"Đã quét {scanned} packet, lấy được {written} packet -> {args.output}")
    for t in types:
        if hits[t]:
            print(f"  + {t}: {hits[t]} packet")
    if written == 0:
        print("⚠️  Không tìm thấy packet nào khớp — thử đổi --type / --port / --flags / --contains.")


if __name__ == "__main__":
    main()