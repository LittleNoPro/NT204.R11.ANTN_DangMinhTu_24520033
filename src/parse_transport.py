from scapy.all import TCP, UDP, ICMP

def parse_transport(packet):
    if TCP in packet:
        tcp = packet[TCP]

        return {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": str(tcp.flags),
            "seq": tcp.seq,
            "ack": tcp.ack,
        }

    elif UDP in packet:
        udp = packet[UDP]

        return {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
        }

    elif ICMP in packet:
        icmp = packet[ICMP]

        return {
            "protocol": "ICMP",
            "type": icmp.type,
            "code": icmp.code,
        }

    return {
        "protocol": "UNKNOWN"
    }