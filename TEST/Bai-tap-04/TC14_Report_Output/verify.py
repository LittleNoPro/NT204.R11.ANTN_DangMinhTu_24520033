"""Kiểm tra TC14: báo cáo text và JSON nhất quán với nhau và với Alert Repository.

Đầu vào: report.txt, report.json (report.py) và alerts.jsonl (report.py -a, cùng khoảng
thời gian). Script tự tính lại số liệu từ danh sách alert rồi so với report.json, và so
các con số trong report.txt với report.json. In từng mục kiểm tra và PASS/FAIL.
"""
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


text = read("report.txt")
report = json.loads(read("report.json"))
alerts = [json.loads(line) for line in read("alerts.jsonl").splitlines() if line.strip()]
results = []


def check(name, expected, actual):
    results.append(expected == actual)
    print(f"{'OK  ' if expected == actual else 'FAIL'} {name}: {actual}"
          + ("" if expected == actual else f" (mong đợi {expected})"))


def events_by(key):
    counter = Counter()
    for alert in alerts:
        counter[key(alert)] += alert["count"]
    return counter


# 1. Repository → JSON: tự tính lại từ alerts.jsonl
summary = report["summary"]
check("total_alerts", len(alerts), summary["total_alerts"])
check("total_events", sum(a["count"] for a in alerts), summary["total_events"])
sev_alerts = Counter(a["severity"] for a in alerts)
sev_events = events_by(lambda a: a["severity"])
check("severity", {s: {"alerts": sev_alerts[s], "events": sev_events[s]} for s in SEVERITIES},
      summary["severity"])
sid_events = events_by(lambda a: a["sid"])
check("top_sids (sid, events)", sorted(sid_events.items(), key=lambda kv: (-kv[1], kv[0]))[:5],
      [(r["sid"], r["events"]) for r in report["top_sids"]])
check("top_src_ips (events)", sorted(events_by(lambda a: a["src_ip"]).values(), reverse=True)[:5],
      [r["events"] for r in report["top_src_ips"]])
check("top_dst_ips (events)", sorted(events_by(lambda a: a["dst_ip"]).values(), reverse=True)[:5],
      [r["events"] for r in report["top_dst_ips"]])
check("protocols", dict(events_by(lambda a: a["protocol"])),
      {r["protocol"]: r["events"] for r in report["protocols"]})
check("timeline (giờ → events)",
      dict(sorted(events_by(lambda a: int(a["first_seen"] // 3600 * 3600)).items())),
      {int(datetime.fromisoformat(r["time"].replace("Z", "+00:00")).timestamp()): r["events"]
       for r in report["timeline"]["rows"]})

# 2. JSON ↔ text: các con số người đọc thấy phải giống bản JSON
line = re.search(r"Total alerts: (\d+) \(events: (\d+)\) \| (.*)", text)
check("text: Total alerts / events", (summary["total_alerts"], summary["total_events"]),
      (int(line.group(1)), int(line.group(2))))
check("text: phân bố severity", {s: summary["severity"][s]["alerts"] for s in SEVERITIES},
      {k.upper(): int(v) for k, v in re.findall(r"(\w+): (\d+)", line.group(3))})
check("text: Period", f"Period: {report['period']['from']} -> {report['period']['to']} (UTC)",
      re.search(r"Period: .*", text).group(0))
top = re.search(r"Top SID: (\d+) \((\d+)\) \| Top source: (\S+) \((\d+)\)", text)
check("text: Top SID / Top source",
      (report["top_sids"][0]["sid"], report["top_sids"][0]["events"],
       report["top_src_ips"][0]["ip"], report["top_src_ips"][0]["events"]),
      (int(top.group(1)), int(top.group(2)), top.group(3), int(top.group(4))))
for section in ("Severity", "Top SID", "Classtype", "Top source IP", "Top destination IP",
                "Transport protocol", "Application protocol", "Alerts per hour"):
    check(f"text: có mục '{section}'", True, f"\n{section}\n" in text)

print("PASS" if all(results) else "FAIL", f"({sum(results)}/{len(results)} mục)")
sys.exit(0 if all(results) else 1)
