import json
import argparse

from scapy.all import sniff

from parse_network import parse_network
from parse_transport import parse_transport
from parse_application import parse_application
from decoder import new_section as new_decoder_section
from preprocessor import new_section as new_preprocess_section
from flow_tracker import new_section as new_flow_section


def process_packet(packet, timestamp):
    event = {
        "timestamp": timestamp,
        "network": parse_network(packet),
        "transport": parse_transport(packet),
        "application": parse_application(packet),
        # 3 section trung gian — module điền giá trị, thiếu dữ liệu → null/[]
        "decoder": new_decoder_section(),
        "preprocess": new_preprocess_section(),
        "flow": new_flow_section(),
    }

    # Chuỗi xử lý — mở rộng từng module khi hoàn thành:
    #   event = decoder.apply(event)
    #   event = preprocessor.apply(event)
    #   event = flow_tracker.track(event)
    return event


def create_handler(outfile, pretty=False):
    state = {"packet_id": 0, "outfile": outfile}

    def handle_packet(packet):
        state["packet_id"] += 1
        timestamp = float(packet.time)
        event = process_packet(packet, timestamp)
        event["packet_id"] = state["packet_id"]

        if pretty:
            text = json.dumps(event, default=str, indent=2, ensure_ascii=False)
        else:
            text = json.dumps(event, default=str, ensure_ascii=False)
        state["outfile"].write(text + "\n")
        print(text, flush=True)

    return handle_packet


def capture(num, outfile, pretty=False, interface=None, filename=None):
    sniff(
        iface=interface,
        offline=filename,
        prn=create_handler(outfile, pretty),
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

    args = parser.parse_args()

    with open(args.output, "w", encoding="utf-8") as outfile:
        capture(args.count, outfile, args.pretty,
                interface=args.interface, filename=args.pcap)
