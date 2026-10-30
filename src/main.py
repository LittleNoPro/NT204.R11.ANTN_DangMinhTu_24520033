import json
import argparse
import sys

from scapy.all import sniff

from parse_network import parse_network
from parse_transport import parse_transport
from parse_application import parse_application
import decoder
import preprocessor
import flow_tracker
import engine as core_engine
from rule_parser import public_view


def process_packet(packet, timestamp):
    event = {
        "timestamp": timestamp,
        "network": parse_network(packet),
        "transport": parse_transport(packet),
        "application": parse_application(packet),
        "decoder": decoder.new_section(),
        "preprocess": preprocessor.new_section(),
        "flow": flow_tracker.new_section(),
    }
    event = decoder.apply(event)
    event = preprocessor.apply(event)
    return event


def dumps(obj):
    return json.dumps(obj, default=str, ensure_ascii=False)


def create_handler(outfile, pretty=False, tracker=None, rule_engine=None,
                   alerts=None, trace=None):
    state = {"packet_id": 0, "outfile": outfile}

    def handle_packet(packet):
        state["packet_id"] += 1
        timestamp = float(packet.time)
        event = process_packet(packet, timestamp)
        if tracker:
            event = tracker.track(event)
        event["packet_id"] = state["packet_id"]

        if rule_engine:
            flow_ctx = tracker.context(event) if tracker else None
            detections, evaluation = rule_engine.evaluate(event, flow_ctx)
            for det in detections:
                alerts.write(dumps(det) + "\n")
            if trace:
                trace.write(dumps(evaluation) + "\n")

        if pretty:
            text = json.dumps(event, default=str, indent=2, ensure_ascii=False)
        else:
            text = json.dumps(event, default=str, ensure_ascii=False)
        state["outfile"].write(text + "\n")
        print(text, flush=True)

    return handle_packet


def capture(num, outfile, pretty=False, interface=None, filename=None,
            tracker=None, **engine_args):
    sniff(
        iface=interface,
        offline=filename,
        prn=create_handler(outfile, pretty, tracker, **engine_args),
        store=False,
        count=num,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple command-line tool.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--interface")
    group.add_argument("--pcap")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output", default="output.jsonl")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--flows", default=None,
                        help="ghi flow đã đóng vào file jsonl")
    parser.add_argument("--tcp-timeout", type=int, default=300)
    parser.add_argument("--udp-timeout", type=int, default=60)
    # --- Core Engine (bài tập 3) ---
    parser.add_argument("--rules", action="append", default=[],
                        help="file .rules (lặp lại được)")
    parser.add_argument("--rules-config", default=None,
                        help="file JSON: rule_files, disabled_sids, variables")
    parser.add_argument("--alerts", default="alerts.jsonl",
                        help="ghi Detection Event (khi có rule)")
    parser.add_argument("--rules-report", default=None,
                        help="ghi Internal Rule Object + status của mọi rule")
    parser.add_argument("--trace", default=None,
                        help="ghi candidate rules + kết quả match từng event")
    parser.add_argument("--stats", default=None,
                        help="ghi thống kê engine (JSON)")
    parser.add_argument("--check-rules", action="store_true",
                        help="chỉ nạp/validate rule rồi thoát")

    args = parser.parse_args()
    if not (args.interface or args.pcap or args.check_rules):
        parser.error("one of --interface, --pcap, --check-rules is required")

    rule_engine = None
    if args.rules or args.rules_config:
        repo, warnings = core_engine.build_repository(args.rules, args.rules_config)
        for warning in warnings:
            print(f"[rules] warning: {warning}", file=sys.stderr)
        print(f"[rules] {repo.summary()}", file=sys.stderr)
        if args.rules_report:
            with open(args.rules_report, "w", encoding="utf-8") as f:
                for rule in repo.rules + repo.rejected:
                    f.write(dumps(public_view(rule)) + "\n")
        rule_engine = core_engine.RuleEngine(repo)
    if args.check_rules:
        sys.exit(0)

    tracker = flow_tracker.FlowTracker(tcp_timeout=args.tcp_timeout,
                                       udp_timeout=args.udp_timeout)
    alerts = open(args.alerts, "w", encoding="utf-8") if rule_engine else None
    trace = open(args.trace, "w", encoding="utf-8") if rule_engine and args.trace else None
    with open(args.output, "w", encoding="utf-8") as outfile:
        capture(args.count, outfile, args.pretty,
                interface=args.interface, filename=args.pcap,
                tracker=tracker, rule_engine=rule_engine,
                alerts=alerts, trace=trace)
    for f in (alerts, trace):
        if f:
            f.close()
    if rule_engine:
        print(f"[engine] {rule_engine.summary()}", file=sys.stderr)
        if args.stats:
            with open(args.stats, "w", encoding="utf-8") as f:
                json.dump(rule_engine.summary(), f, indent=2)

    if args.flows:
        with open(args.flows, "w", encoding="utf-8") as f:
            for flow in tracker.flush():
                f.write(json.dumps(flow, default=str, ensure_ascii=False) + "\n")
    else:
        tracker.flush()
