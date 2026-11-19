"""Kiểm tra TC09: alert đọc lại từ Alert Repository không mất trường.

So từng Alert Object trong alerts.jsonl (đọc từ repo.db bằng report.py -a) với
Detection Event tương ứng trong detections.jsonl (ghép theo sid + packet_id):
- có đủ mọi cột của bảng alerts (alert_store.ALERT_COLUMNS)
- trường bắt buộc khác null
- giá trị khớp Detection Event (first_seen = timestamp của event)
- alert_id không trùng, kể cả giữa các lần chạy dùng chung repo.db
In bảng kết quả và PASS/FAIL; exit code 1 nếu FAIL.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "src"))
from alert_store import ALERT_COLUMNS        # noqa: E402

REQUIRED = ("alert_id", "sid", "severity", "protocol", "src_ip", "dst_ip",
            "first_seen", "last_seen", "count")
COPIED = ("sid", "rev", "msg", "priority", "classtype", "protocol", "application_protocol",
          "src_ip", "src_port", "dst_ip", "dst_port", "flow_id", "packet_id")


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


detections = {(d["sid"], d["packet_id"]): d for d in load("detections.jsonl")}
alerts = load("alerts.jsonl")
ok = True
for alert in alerts:
    problems = [f"thiếu cột {c}" for c in ALERT_COLUMNS if c not in alert]
    problems += [f"{c} = null" for c in REQUIRED if alert.get(c) is None]
    detection = detections.get((alert["sid"], alert["packet_id"]))
    if detection is None:
        problems.append("không có Detection Event tương ứng")
    else:
        problems += [f"{c}: {alert[c]!r} != {detection[c]!r}"
                     for c in COPIED if alert.get(c) != detection.get(c)]
        if alert["first_seen"] != detection["timestamp"]:
            problems.append("first_seen != timestamp")
    ok &= not problems
    print(f"{alert['alert_id']}  sid={alert['sid']:<8} {len(alert)} trường  "
          + ("OK" if not problems else "; ".join(problems)))
ids = [a["alert_id"] for a in alerts]
if len(set(ids)) != len(ids):
    ok = False
    print("alert_id bị trùng:", sorted(i for i in set(ids) if ids.count(i) > 1))
print(f"{len(alerts)} alert, {len(ALERT_COLUMNS)} cột mỗi alert, alert_id duy nhất:",
      "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
