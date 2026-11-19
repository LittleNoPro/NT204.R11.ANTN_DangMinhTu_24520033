"""Sinh input.jsonl cho TC10 — truy vấn Alert Repository.

8 Detection Event trải từ 00:10 tới 03:00 ngày 2025-11-15 (UTC), khác nhau về SID,
severity, IP và protocol. Không có hai event nào cùng khóa trong 60 giây, nên mỗi event
thành một alert (A000001–A000008 theo thứ tự dưới đây).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 1763164800.0                  # 2025-11-15T00:00:00Z

RULES = {   # sid: (msg, priority, classtype)
    4100001: ("Directory traversal", 1, "web-application-attack"),
    4100002: ("SQL injection", 2, "web-application-attack"),
    4100003: ("DNS query malware domain", 2, "trojan-activity"),
    4100004: ("SSH brute force", 3, "attempted-admin"),
}
EVENTS = [  # (phút, sid, protocol, src_ip, src_port, dst_ip, dst_port)
    (10, 4100001, "TCP", "10.0.0.5", 52133, "192.168.1.20", 80),
    (50, 4100002, "TCP", "10.0.0.6", 40001, "192.168.1.20", 80),
    (65, 4100001, "TCP", "10.0.0.5", 52134, "192.168.1.21", 80),
    (80, 4100002, "TCP", "10.0.0.7", 40002, "192.168.1.20", 80),
    (95, 4100003, "UDP", "10.0.0.8", 5353, "192.168.1.53", 53),
    (110, 4100004, "TCP", "10.0.0.5", 52135, "192.168.1.20", 22),
    (135, 4100003, "UDP", "10.0.0.8", 5353, "192.168.1.53", 53),
    (180, 4100001, "TCP", "10.0.0.9", 52136, "192.168.1.20", 80),
]

with open(os.path.join(HERE, "input.jsonl"), "w", encoding="utf-8") as f:
    for packet_id, (minute, sid, proto, src, sport, dst, dport) in enumerate(EVENTS, 1):
        msg, priority, classtype = RULES[sid]
        f.write(json.dumps({
            "timestamp": BASE + minute * 60, "packet_id": packet_id,
            "sid": sid, "rev": 1, "msg": msg, "priority": priority, "classtype": classtype,
            "protocol": proto, "application_protocol": "DNS" if dport == 53 else None,
            "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
            "flow_id": f"flow-{packet_id:04d}",
        }) + "\n")
print("wrote", os.path.join(HERE, "input.jsonl"), f"({len(EVENTS)} events)")
