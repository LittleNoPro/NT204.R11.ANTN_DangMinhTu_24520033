import argparse
import time
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


def handle_packet(packet):
    timestamp = float(packet.time)
    event = process_packet(packet, timestamp)
    print(event)
  
def live_capture(interface, num):
    sniff(
        iface=interface,
        prn=handle_packet,
        store=False,
        count=num,
    )


def pcap_capture(filename, num):
    sniff(
        offline=filename,
        prn=handle_packet,
        store=False,
        count=num,
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple command-line tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface")
    group.add_argument("--pcap")
    parser.add_argument("--count", type=int, default=10)

    args = parser.parse_args()

    if args.interface:
        live_capture(args.interface, args.count)
    elif args.pcap:
        pcap_capture(args.pcap, args.count)