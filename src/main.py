import json
import argparse

from scapy.all import sniff

from parse_network import parse_network
from parse_transport import parse_transport
from parse_application import parse_application
import decoder
import preprocessor
import flow_tracker


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


def create_handler(outfile, pretty=False, tracker=None):
    state = {"packet_id": 0, "outfile": outfile}

    def handle_packet(packet):
        state["packet_id"] += 1
        timestamp = float(packet.time)
        event = process_packet(packet, timestamp)
        if tracker:
            event = tracker.track(event)
        event["packet_id"] = state["packet_id"]

        if pretty:
            text = json.dumps(event, default=str, indent=2, ensure_ascii=False)
        else:
            text = json.dumps(event, default=str, ensure_ascii=False)
        state["outfile"].write(text + "\n")
        print(text, flush=True)

    return handle_packet


def capture(num, outfile, pretty=False, interface=None, filename=None,
            tracker=None):
    sniff(
        iface=interface,
        offline=filename,
        prn=create_handler(outfile, pretty, tracker),
        store=False,
        count=num,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple command-line tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface")
    group.add_argument("--pcap")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output", default="output.jsonl")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--flows", default=None,
                        help="ghi flow đã đóng vào file jsonl")
    parser.add_argument("--tcp-timeout", type=int, default=300)
    parser.add_argument("--udp-timeout", type=int, default=60)

    args = parser.parse_args()

    tracker = flow_tracker.FlowTracker(tcp_timeout=args.tcp_timeout,
                                       udp_timeout=args.udp_timeout)
    with open(args.output, "w", encoding="utf-8") as outfile:
        capture(args.count, outfile, args.pretty,
                interface=args.interface, filename=args.pcap,
                tracker=tracker)

    if args.flows:
        with open(args.flows, "w", encoding="utf-8") as f:
            for flow in tracker.flush():
                f.write(json.dumps(flow, default=str, ensure_ascii=False) + "\n")
    else:
        tracker.flush()
