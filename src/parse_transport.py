from scapy.all import TCP, UDP, ICMP, Raw

def parse_transport(packet):
    if TCP in packet:
        tcp = packet[TCP]
        payload = bytes(tcp.payload) if Raw in tcp else b""

        return {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": str(tcp.flags),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "payload_length": len(payload), 
            "payload_preview": payload[:].decode("utf-8", errors="ignore") if payload else None,
        }

    elif UDP in packet:
        udp = packet[UDP]
        payload = bytes(udp.payload) if Raw in udp else b"" 

        return {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "payload_length": len(payload),
            "payload_preview": payload[:].decode("utf-8", errors="ignore")
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