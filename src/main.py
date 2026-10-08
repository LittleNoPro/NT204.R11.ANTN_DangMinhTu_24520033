import json
import argparse

from scapy.all import sniff

from parse_network import parse_network
from parse_transport import parse_transport
from parse_application import parse_application

# =============================================================================
# Bai tap 2 - 3 section trên event
# Parser (Bai tap 1) sinh 4 lớp; decoder / preprocessor / flow_tracker sẽ điền
# giá trị vào 3 section dưới đây. Thiếu dữ liệu → null (field) / [] (list).
# =============================================================================
DECODER_SECTION_SCHEMA = {
    "uri_raw": None,
    "uri_decoded": None,
    "text_decoded": None,
    "body_decoded": None,
    "decode_method": None,     # percent | html_entity | base64 | quoted_printable | none
    "decode_status": None,     # ok | partial | error | not_applicable
    "decode_reason": None,
}

PREPROCESS_SECTION_SCHEMA = {
    "preprocess_status": None,     # valid | partial | invalid
    "processing_action": None,     # continue | skip
    "reason": None,
    "normalized": {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "host": None,
        "path": None,
        "header_names": [],        # list → thiếu dữ liệu dùng [] (yêu cầu §4)
        "timestamp": None,
    },
}

FLOW_SECTION_SCHEMA = {
    "flow_id": None,
    "direction": None,   # forward | backward
    "state": None,       # NEW | HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET
}


def new_sections():
    """3 section Bài tập 2 — copy cho từng event, không share nested dict."""
    return {
        "decoder": dict(DECODER_SECTION_SCHEMA),
        "preprocess": {
            **PREPROCESS_SECTION_SCHEMA,
            "normalized": dict(PREPROCESS_SECTION_SCHEMA["normalized"]),
        },
        "flow": dict(FLOW_SECTION_SCHEMA),
    }


def process_packet(packet, timestamp):
    event = {
        "timestamp": timestamp,
        "network": parse_network(packet),
        "transport": parse_transport(packet),
        "application": parse_application(packet),
        **new_sections(),
    }

    # Chuỗi stage Bài tập 2 — mở rộng từng module khi hoàn thành:
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
