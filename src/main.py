"""IDS: bắt packet, đưa qua pipeline phát hiện và ghi kết quả ra JSON Lines.

Luồng xử lý (số bước khớp với sơ đồ assets/architecture.png):
    khởi động   load_rules(): Rule Loader → Rule Parser → Rule Repository
    mỗi packet  process_packet(): parse → decode → preprocess → flow → engine
                → Detection Event → Alert Manager (severity, lọc, gom) → Alert Repository
    kết thúc    đóng các flow còn mở, in thống kê

Báo cáo từ Alert Repository: python src/report.py

Ví dụ:
    python src/main.py -r capture.pcap -c rules/engine.json -l logs
    sudo python src/main.py -i eth0 -c rules/engine.json
    python src/main.py -T -c rules/engine.json
    python src/main.py -D logs/detections.jsonl -c rules/engine.json -l retune
"""

import argparse
import contextlib
import itertools
import json
import os
import sys

from scapy.all import sniff

from parse_network import parse_network
from parse_transport import parse_transport
from parse_application import parse_application
import decoder
import preprocessor
import flow_tracker
import engine
import rule_loader
from alert import AlertManager, fast_line
from alert_store import AlertStore
from rule_parser import public_view


def dumps(obj):
    return json.dumps(obj, default=str, ensure_ascii=False)


def process_packet(packet, packet_id, tracker, rule_engine):
    """Đưa một packet qua toàn bộ pipeline. Trả về (event, alerts, trace)."""
    event = {
        "timestamp": float(packet.time),
        "network": parse_network(packet),              # 2. parse L3
        "transport": parse_transport(packet),          #    parse L4
        "application": parse_application(packet),      #    parse L7
        "decoder": decoder.new_section(),
        "preprocess": preprocessor.new_section(),
        "flow": flow_tracker.new_section(),
        "packet_id": packet_id,
    }
    decoder.apply(event)                               # 3. giải mã
    preprocessor.apply(event)                          # 4. kiểm tra + chuẩn hóa
    tracker.track(event)                               # 5. gán flow
    if rule_engine is None:
        return event, [], None
    alerts, trace = rule_engine.evaluate(event, tracker.context(event))   # 6–10. so rule
    return event, alerts, trace


def load_rules(args, config):
    """Khởi động: nạp và kiểm tra rule. Trả về RuleEngine, hoặc None nếu không có rule."""
    if not (config["rule_files"] or args.rules):
        return None
    repo, warnings = engine.build_repository(args.rules, config)
    for warning in warnings:
        print(f"[rules] warning: {warning}", file=sys.stderr)
    print(f"[rules] {repo.summary()}", file=sys.stderr)
    if args.verbose:
        with open(os.path.join(args.log_dir, "rules_report.jsonl"), "w", encoding="utf-8") as f:
            for rule in repo.rules + repo.rejected:
                f.write(dumps(public_view(rule)) + "\n")
    return engine.RuleEngine(repo)


def open_store(args, config):
    """Alert Repository. Mặc định <thư mục log>/alerts.db: thuộc về lần chạy này
    nên được tạo mới như các file log khác. storage.path đặt riêng thì là kho
    dùng chung lâu dài: giữ alert cũ, alert_id đánh tiếp."""
    path = config["alert"]["storage"]["path"]
    if path is None:
        path = os.path.join(args.log_dir, "alerts.db")
        if os.path.exists(path):
            os.remove(path)
    return AlertStore(path)


def open_alerting(args, config, files):
    """Alert Module: Alert Manager + Alert Repository + fast.log.
    Trả về (raise_alert, manager); raise_alert(detection) xử lý một Detection Event."""
    fast_log = files.enter_context(
        open(os.path.join(args.log_dir, "fast.log"), "w", encoding="utf-8"))
    store = files.enter_context(open_store(args, config))
    manager = AlertManager(config["alert"], next_id=store.next_id())

    def raise_alert(detection):                         # 11. Detection Event → alert
        status, alert, reason = manager.process(detection)
        if status in ("alert", "aggregated"):
            store.save(alert)
        else:                                           # rejected | filtered
            store.discard(status, reason, alert or detection)
        if status == "alert":
            line = fast_line(alert)
            fast_log.write(line + "\n")
            if args.verbose:
                print(line, file=sys.stderr)
        elif status == "rejected" and args.verbose:
            print(f"[alert] rejected: {reason}", file=sys.stderr)

    return raise_alert, manager


def replay_detections(path, raise_alert):
    """Đưa Detection Event đã lưu (JSON Lines) qua Alert Module, không cần packet:
    dùng để chỉnh lại severity/lọc/gom nhóm trên dữ liệu cũ. Dòng không phải JSON
    hợp lệ vẫn được chuyển vào để bị từ chối kèm lý do, không làm dừng chương trình."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                detection = json.loads(line)
            except ValueError:
                detection = line.strip()
            raise_alert(detection)


def parse_args():
    parser = argparse.ArgumentParser(
        description="IDS dựa trên rule cú pháp Snort. Thiết lập chi tiết nằm trong file cấu hình (-c).")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", dest="interface", metavar="IFACE",
                        help="bắt trực tiếp trên card mạng (cần root)")
    source.add_argument("-r", dest="pcap", metavar="PCAP", help="đọc từ file PCAP")
    source.add_argument("-D", dest="detections", metavar="JSONL",
                        help="đọc Detection Event đã lưu, chỉ chạy Alert Module")
    parser.add_argument("-c", dest="config", metavar="CONFIG",
                        help="file cấu hình JSON: rule, biến, timeout, chính sách (vd rules/engine.json)")
    parser.add_argument("-s", dest="rules", metavar="RULES", action="append", default=[],
                        help="nạp thêm file .rules (lặp lại được)")
    parser.add_argument("-l", dest="log_dir", metavar="DIR", default="logs",
                        help="thư mục ghi log và alerts.db (mặc định: logs)")
    parser.add_argument("-n", dest="count", metavar="N", type=int, default=0,
                        help="dừng sau N packet (mặc định: không giới hạn)")
    parser.add_argument("-T", dest="test", action="store_true",
                        help="chỉ nạp và kiểm tra rule rồi thoát")
    parser.add_argument("-v", dest="verbose", action="store_true",
                        help="in alert ra console, ghi thêm trace.jsonl và rules_report.jsonl")
    args = parser.parse_args()
    if not (args.interface or args.pcap or args.detections or args.test):
        parser.error("cần -i, -r, -D hoặc -T")
    return args


def main():
    args = parse_args()
    try:
        config = rule_loader.load_config(args.config)
    except rule_loader.ConfigError as error:
        sys.exit(f"[config] {error}")
    preprocessor.configure(skip_unknown=config["skip_unknown"],
                           max_payload=config["max_payload"])
    os.makedirs(args.log_dir, exist_ok=True)

    if args.detections:
        with contextlib.ExitStack() as files:
            raise_alert, manager = open_alerting(args, config, files)
            try:
                replay_detections(args.detections, raise_alert)
            except OSError as error:
                sys.exit(f"[detections] không đọc được {args.detections}: {error.strerror}")
        print(f"[alert] {dict(manager.stats)}", file=sys.stderr)
        return

    rule_engine = load_rules(args, config)
    if args.test:
        if rule_engine is None:
            sys.exit("-T: không có rule nào để kiểm tra (dùng -c hoặc -s)")
        return

    with contextlib.ExitStack() as files:
        def open_log(name):
            path = os.path.join(args.log_dir, name)
            return files.enter_context(open(path, "w", encoding="utf-8"))

        events = open_log("events.jsonl")
        flows = open_log("flows.jsonl")
        detections_log = open_log("detections.jsonl") if rule_engine else None
        trace = open_log("trace.jsonl") if rule_engine and args.verbose else None
        if rule_engine:
            raise_alert, alert_manager = open_alerting(args, config, files)

        def write_flow(flow):
            flows.write(dumps(flow) + "\n")
            flows.flush()

        tracker = flow_tracker.FlowTracker(tcp_timeout=config["flow_timeout"]["tcp"],
                                           udp_timeout=config["flow_timeout"]["udp"],
                                           on_close=write_flow)
        packet_ids = itertools.count(1)

        def handle(packet):
            event, detections, evaluation = process_packet(packet, next(packet_ids),
                                                           tracker, rule_engine)
            for detection in detections:
                detections_log.write(dumps(detection) + "\n")
                raise_alert(detection)
            if trace:
                trace.write(dumps(evaluation) + "\n")
            events.write(dumps(event) + "\n")

        try:
            sniff(iface=args.interface, offline=args.pcap, prn=handle, store=False,
                  count=args.count)
        finally:
            tracker.flush()                            # ghi các flow còn mở, kể cả khi lỗi

    if rule_engine:
        print(f"[engine] {rule_engine.summary()}", file=sys.stderr)
        print(f"[alert] {dict(alert_manager.stats)}", file=sys.stderr)


if __name__ == "__main__":
    main()
