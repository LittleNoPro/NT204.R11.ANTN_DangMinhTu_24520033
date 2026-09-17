import json
import argparse
from scapy.all import Ether, IP, IPv6, ICMP, TCP, UDP, sniff, DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

from parse_network import parse_network 
from parse_transport import parse_transport
from parse_application import parse_application 

def process_packet(packet, timestamp):
    event = {
        "timestamp": timestamp,
        "network": parse_network(packet), 
        "transport": parse_transport(packet),
        "application": parse_application(packet)
    }

    return event


def create_handler(outfile):
    state = {"packet_id": 0, "outfile": outfile}

    def handle_packet(packet):
        state["packet_id"] += 1
        timestamp = float(packet.time)
        event = process_packet(packet, timestamp)
        event["packet_id"] = state["packet_id"]

        line = json.dumps(event, default=str)
        state["outfile"].write(line + "\n")

        print(line)

    return handle_packet


def live_capture(interface, num, outfile):
    sniff(
        iface=interface,
        prn=create_handler(outfile),
        store=False,
        count=num,
    )

def pcap_capture(filename, num, outfile):
    sniff(
        offline=filename,
        prn=create_handler(outfile),
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

    args = parser.parse_args()

    with open(args.output, "w", encoding="utf-8") as outfile:
        if args.interface:
            live_capture(args.interface, args.count, outfile)
        elif args.pcap:
            pcap_capture(args.pcap, args.count, outfile)