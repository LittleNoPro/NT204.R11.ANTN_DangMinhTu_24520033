import argparse
import time
from scapy.all import Ether, IP, IPv6, ICMP, TCP, UDP, sniff

def parse_packet(packet, timestamp):
    print("=" * 70)
    print(f"Timestamp : {timestamp:.6f}")

    # ---------------------------------------------------------
    # Ethernet Layer
    # ---------------------------------------------------------
    if Ether in packet:
        ethernet = packet[Ether]

        print("Layer 2   : Ethernet")
        print(f"MAC src   : {ethernet.src}")
        print(f"MAC dst   : {ethernet.dst}")

    # ---------------------------------------------------------
    # IPv4
    # ---------------------------------------------------------
    if IP in packet:
        ip = packet[IP]

        print("Layer 3   : IPv4")
        print(f"IP src    : {ip.src}")
        print(f"IP dst    : {ip.dst}")
        print(f"TTL       : {ip.ttl}")
        print(f"Protocol  : {ip.proto}")

    # ---------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------
    elif IPv6 in packet:
        ipv6 = packet[IPv6]

        print("Layer 3   : IPv6")
        print(f"IP src    : {ipv6.src}")
        print(f"IP dst    : {ipv6.dst}")

    # ---------------------------------------------------------
    # TCP
    # ---------------------------------------------------------
    if TCP in packet:
        tcp = packet[TCP]

        print("Layer 4   : TCP")
        print(f"Src port  : {tcp.sport}")
        print(f"Dst port  : {tcp.dport}")
        print(f"Flags     : {tcp.flags}")

    # ---------------------------------------------------------
    # UDP
    # ---------------------------------------------------------
    elif UDP in packet:
        udp = packet[UDP]

        print("Layer 4   : UDP")
        print(f"Src port  : {udp.sport}")
        print(f"Dst port  : {udp.dport}")

    # ---------------------------------------------------------
    # ICMP
    # ---------------------------------------------------------
    elif ICMP in packet:
        icmp = packet[ICMP]

        print("Layer 4   : ICMP")
        print(f"Type      : {icmp.type}")
        print(f"Code      : {icmp.code}")

    print(f"Summary   : {packet.summary()}")

def handle_packet(packet):
    timestamp = float(packet.time)
    parse_packet(packet, timestamp)
  
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