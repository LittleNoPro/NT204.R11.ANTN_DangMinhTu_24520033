"""Sinh input.jsonl cho TC11 — thống kê severity.

16 Detection Event ngày 2025-11-15 (UTC). Có event lặp để kiểm tra aggregation
(alerts khác events) và một SID bị suppress để kiểm tra event bị lọc không được đếm.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 1763164800.0                  # 2025-11-15T00:00:00Z

RULES = {   # sid: (msg, priority) — severity theo map mặc định: 1 CRITICAL … 4 LOW
    4110001: ("Directory traversal", 1),
    4110002: ("SQL injection", 2),
    4110003: ("Port scan", 3),
    4110004: ("Suspicious user-agent", 4),
    4110005: ("Known scanner (suppressed)", 4),
}
EVENTS = [  # (giây từ 00:00, sid, src_ip, dst_ip)
    (0, 4110001, "10.0.0.5", "192.168.1.20"),        # CRITICAL nhóm 1
    (10, 4110001, "10.0.0.5", "192.168.1.20"),
    (20, 4110001, "10.0.0.5", "192.168.1.20"),
    (100, 4110002, "10.0.0.7", "192.168.1.20"),      # HIGH nhóm 1
    (200, 4110003, "10.0.0.9", "192.168.1.22"),      # MEDIUM
    (300, 4110002, "10.0.0.7", "192.168.1.20"),      # HIGH nhóm 2 (cách 200 s > 60)
    (400, 4110004, "10.0.0.5", "192.168.1.20"),      # LOW nhóm 1
    (430, 4110004, "10.0.0.5", "192.168.1.20"),
    (500, 4110005, "10.0.0.250", "192.168.1.20"),    # bị suppress
    (510, 4110005, "10.0.0.250", "192.168.1.20"),
    (520, 4110005, "10.0.0.250", "192.168.1.20"),
    (3600, 4110001, "10.0.0.6", "192.168.1.20"),     # 01:00 CRITICAL nhóm 2
    (3630, 4110001, "10.0.0.6", "192.168.1.20"),
    (3700, 4110002, "10.0.0.8", "192.168.1.21"),     # HIGH nhóm 3
    (3710, 4110002, "10.0.0.8", "192.168.1.21"),
    (5000, 4110004, "10.0.0.5", "192.168.1.20"),     # LOW nhóm 2
]

with open(os.path.join(HERE, "input.jsonl"), "w", encoding="utf-8") as f:
    for packet_id, (second, sid, src, dst) in enumerate(EVENTS, 1):
        msg, priority = RULES[sid]
        f.write(json.dumps({
            "timestamp": BASE + second, "packet_id": packet_id,
            "sid": sid, "rev": 1, "msg": msg, "priority": priority,
            "classtype": "attempted-recon", "protocol": "TCP", "application_protocol": "HTTP",
            "src_ip": src, "src_port": 40000 + packet_id, "dst_ip": dst, "dst_port": 80,
            "flow_id": f"flow-{packet_id:04d}",
        }) + "\n")
print("wrote", os.path.join(HERE, "input.jsonl"), f"({len(EVENTS)} events)")
