"""Sinh input.jsonl cho TC12 — xếp hạng Top-N SID và IP.

17 Detection Event ngày 2025-11-15 (UTC). Thiết kế để:
- xếp theo events (số Detection Event thật) khác xếp theo alerts: SID 4120001 chỉ có
  1 alert nhưng 6 events (bị gộp);
- có hòa về events, phân định bằng số alert: 4120002 và 4120003 cùng 4 events;
- có nhiều mục hơn top_n = 3.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 1763164800.0                  # 2025-11-15T00:00:00Z

MSGS = {4120001: "Brute force burst", 4120002: "SQL injection", 4120003: "Directory traversal",
        4120004: "XSS attempt", 4120005: "Port scan"}
EVENTS = (  # (giây từ 00:00, sid, src_ip, dst_ip)
    [(s, 4120001, "10.0.0.5", "192.168.1.20") for s in (0, 10, 20, 30, 40, 50)]     # 1 nhóm
    + [(s, 4120002, "10.0.0.6", "192.168.1.20") for s in (1000, 2000, 3000, 4000)]  # 4 nhóm
    + [(s, 4120003, "10.0.0.7", "192.168.1.21") for s in (1500, 1510, 2500, 2510)]  # 2 nhóm
    + [(5000, 4120004, "10.0.0.8", "192.168.1.22"), (5100, 4120004, "10.0.0.5", "192.168.1.22")]
    + [(6000, 4120005, "10.0.0.9", "192.168.1.23")]
)

with open(os.path.join(HERE, "input.jsonl"), "w", encoding="utf-8") as f:
    for packet_id, (second, sid, src, dst) in enumerate(EVENTS, 1):
        f.write(json.dumps({
            "timestamp": BASE + second, "packet_id": packet_id,
            "sid": sid, "rev": 1, "msg": MSGS[sid], "priority": 2,
            "classtype": "web-application-attack", "protocol": "TCP", "application_protocol": "HTTP",
            "src_ip": src, "src_port": 40000 + packet_id, "dst_ip": dst, "dst_port": 80,
            "flow_id": f"flow-{packet_id:04d}",
        }) + "\n")
print("wrote", os.path.join(HERE, "input.jsonl"), f"({len(EVENTS)} events)")
