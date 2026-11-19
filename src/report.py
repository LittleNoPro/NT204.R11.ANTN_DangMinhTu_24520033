"""Report Generator: đọc Alert Repository và sinh báo cáo cho một khoảng thời gian.

Chỉ đọc alert đã lưu (alerts.db), không cần packet hay rule. Kết quả gồm:
- báo cáo text in ra stdout (cho người đọc)
- báo cáo JSON ghi ra file (cho máy đọc, mặc định <thư mục log>/report.json)

Hai bản dựng từ cùng một dict nên số liệu luôn khớp nhau.
Với -a, in thẳng các Alert Object khớp truy vấn (JSON Lines) thay cho báo cáo.

"alerts" là số alert (sau aggregation); "events" là tổng count, tức số
Detection Event thật. Bảng Top-N xếp theo events.

Ví dụ:
    python src/report.py -c rules/engine.json -l logs
    python src/report.py -c rules/engine.json --from 2026-11-15 --to "2026-11-16 23:59"
    python src/report.py -c rules/engine.json --from 2026-11-15 --severity HIGH --src 10.0.0.5
    python src/report.py -c rules/engine.json -a --sid 100001 > alerts.jsonl
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import rule_loader
from alert import SEVERITIES, iso_time
from alert_store import AlertStore

BUCKETS = {"hour": 3600, "minute": 60}


def parse_time(text, end=False):
    """Epoch, "2026-11-15", "2026-11-15 10:30" hoặc ISO 8601 → epoch (UTC nếu
    không ghi múi giờ). Với --to, ngày/phút không ghi giây được tính hết phút/ngày
    đó: --to 2026-11-16 nghĩa là tới 23:59:59."""
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"thời gian không hợp lệ: {text!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    value = parsed.timestamp()
    if end:
        digits = sum(ch.isdigit() for ch in text.split("+")[0])
        if digits == 8:                 # chỉ có ngày
            value += 86400 - 1
        elif digits == 12:              # tới phút
            value += 60 - 1
    return value


def _ranking(alerts, key, top_n=None):
    """[(giá trị, alerts, events)] sắp theo events giảm dần rồi alerts, giá trị."""
    counts, events = Counter(), Counter()
    for alert in alerts:
        value = key(alert)
        counts[value] += 1
        events[value] += alert["count"]
    rows = sorted(counts, key=lambda v: (-events[v], -counts[v], str(v)))
    return [(v, counts[v], events[v]) for v in rows[:top_n]]


def build_report(alerts, start, end, filters, top_n, bucket):
    first = min((a["first_seen"] for a in alerts), default=None)
    last = max((a["last_seen"] for a in alerts), default=None)
    period_from = start if start is not None else first
    period_to = end if end is not None else last

    msgs = {a["sid"]: a["msg"] for a in alerts}
    severity = Counter(a["severity"] for a in alerts)
    severity_events = Counter()
    for alert in alerts:
        severity_events[alert["severity"]] += alert["count"]

    step = BUCKETS[bucket]

    def rows(name, key, limit=None):
        return [{name: value, "alerts": n, "events": e}
                for value, n, e in _ranking(alerts, key, limit)]

    timeline = [{"time": iso_time(t), "alerts": n, "events": e}
                for t, n, e in sorted(_ranking(alerts, lambda a: a["first_seen"] // step * step))]
    return {
        "title": "IDS SECURITY REPORT",
        "period": {"from": iso_time(period_from) if period_from is not None else None,
                   "to": iso_time(period_to) if period_to is not None else None},
        "filters": filters,
        "summary": {
            "total_alerts": len(alerts),
            "total_events": sum(a["count"] for a in alerts),
            "severity": {s: {"alerts": severity[s], "events": severity_events[s]}
                         for s in SEVERITIES},
        },
        "top_sids": [{"sid": sid, "msg": msgs[sid], "alerts": n, "events": e}
                     for sid, n, e in _ranking(alerts, lambda a: a["sid"], top_n)],
        "classtypes": rows("classtype", lambda a: a["classtype"] or "unknown", top_n),
        "top_src_ips": rows("ip", lambda a: a["src_ip"], top_n),
        "top_dst_ips": rows("ip", lambda a: a["dst_ip"], top_n),
        "protocols": rows("protocol", lambda a: a["protocol"]),
        "application_protocols": rows("protocol", lambda a: a["application_protocol"] or "none"),
        "timeline": {"bucket": bucket, "rows": timeline},
    }


def render_text(report):
    summary, period = report["summary"], report["period"]
    lines = [
        report["title"],
        f"Period: {period['from'] or '-'} -> {period['to'] or '-'} (UTC)",
    ]
    if report["filters"]:
        lines.append("Filters: " + ", ".join(f"{k}={v}" for k, v in report["filters"].items()))
    lines.append(f"Total alerts: {summary['total_alerts']} (events: {summary['total_events']}) | "
                 + " | ".join(f"{s.title()}: {summary['severity'][s]['alerts']}" for s in SEVERITIES))
    if report["top_sids"]:
        top_sid, top_src = report["top_sids"][0], report["top_src_ips"][0]
        lines.append(f"Top SID: {top_sid['sid']} ({top_sid['events']}) | "
                     f"Top source: {top_src['ip']} ({top_src['events']})")
    else:
        lines.append("Không có alert trong khoảng thời gian này.")

    def table(title, rows, label, key):
        lines.extend(["", title])
        if not rows:
            lines.append("  (trống)")
        for row in rows:
            lines.append(f"  {label(row):<44} alerts={row['alerts']:<5} events={row[key]}")

    table("Severity", [{"name": s, **summary["severity"][s]} for s in SEVERITIES],
          lambda r: r["name"], "events")
    table("Top SID", report["top_sids"], lambda r: f"{r['sid']}  {r['msg']}", "events")
    table("Classtype", report["classtypes"], lambda r: r["classtype"], "events")
    table("Top source IP", report["top_src_ips"], lambda r: r["ip"], "events")
    table("Top destination IP", report["top_dst_ips"], lambda r: r["ip"], "events")
    table("Transport protocol", report["protocols"], lambda r: r["protocol"], "events")
    table("Application protocol", report["application_protocols"], lambda r: r["protocol"], "events")
    table(f"Alerts per {report['timeline']['bucket']}", report["timeline"]["rows"],
          lambda r: r["time"], "events")
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description="Báo cáo từ Alert Repository của IDS.")
    parser.add_argument("-c", dest="config", metavar="CONFIG",
                        help="file cấu hình JSON (storage path, report.top_n)")
    parser.add_argument("-l", dest="log_dir", metavar="DIR", default="logs",
                        help="thư mục log chứa alerts.db khi storage.path = null (mặc định: logs)")
    parser.add_argument("--from", dest="start", metavar="TIME", type=parse_time,
                        help="từ thời điểm (vd 2026-11-15, \"2026-11-15 08:00\", epoch)")
    parser.add_argument("--to", dest="end", metavar="TIME",
                        type=lambda text: parse_time(text, end=True), help="tới thời điểm")
    parser.add_argument("--severity", action="append", choices=SEVERITIES,
                        help="chỉ lấy severity này (lặp lại được)")
    parser.add_argument("--sid", type=int, action="append", help="chỉ lấy SID này (lặp lại được)")
    parser.add_argument("--src", metavar="IP", help="chỉ lấy source IP này")
    parser.add_argument("--dst", metavar="IP", help="chỉ lấy destination IP này")
    parser.add_argument("--protocol", type=str.upper, help="chỉ lấy protocol này (TCP, UDP...)")
    parser.add_argument("-n", dest="top_n", metavar="N", type=int, help="số dòng Top-N (ghi đè report.top_n)")
    parser.add_argument("--bucket", choices=BUCKETS, default="hour",
                        help="chia alert theo giờ hoặc phút (mặc định: hour)")
    parser.add_argument("-a", dest="list_alerts", action="store_true",
                        help="in danh sách alert khớp truy vấn (JSON Lines) thay cho báo cáo")
    parser.add_argument("-o", dest="output", metavar="FILE",
                        help="file báo cáo JSON (mặc định: <thư mục log>/report.json)")
    args = parser.parse_args()
    if args.start is not None and args.end is not None and args.start > args.end:
        parser.error("--from phải trước --to")
    if args.top_n is not None and args.top_n <= 0:
        parser.error("-n phải > 0")
    return args


def main():
    args = parse_args()
    try:
        config = rule_loader.load_config(args.config)
    except rule_loader.ConfigError as error:
        sys.exit(f"[config] {error}")

    filters = {k: v for k, v in (("severity", args.severity), ("sid", args.sid), ("src_ip", args.src),
                                 ("dst_ip", args.dst), ("protocol", args.protocol)) if v}
    db_path = config["alert"]["storage"]["path"] or os.path.join(args.log_dir, "alerts.db")
    if os.path.exists(db_path):
        with AlertStore(db_path) as store:
            alerts = store.query(start=args.start, end=args.end, **filters)
    else:
        print(f"[report] chưa có {db_path}, báo cáo rỗng", file=sys.stderr)
        alerts = []

    if args.list_alerts:
        for alert in alerts:
            print(json.dumps(alert, ensure_ascii=False))
        return
    report = build_report(alerts, args.start, args.end, filters,
                          args.top_n or config["report"]["top_n"], args.bucket)
    print(render_text(report))
    output = args.output or os.path.join(args.log_dir, "report.json")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[report] JSON: {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
