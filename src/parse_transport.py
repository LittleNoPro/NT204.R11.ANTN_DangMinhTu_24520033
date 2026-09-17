from scapy.all import TCP, UDP, ICMP, Raw

# Normalized schema: mọi packet đều trả đúng các key này (thiếu thì None)
def parse_transport(packet):
    schema = {
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "seq": None,
        "ack": None,
        "length": None,
        "type": None,
        "code": None,
        "payload_length": None,
        "payload": None,
    }

    if TCP in packet:
        tcp = packet[TCP]
        payload = bytes(tcp.payload) if Raw in tcp else b""

        return {
            **schema,
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": str(tcp.flags),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "payload_length": len(payload),
            "payload": payload.decode("utf-8", errors="ignore") if payload else None,
        }

    if UDP in packet:
        udp = packet[UDP]
        payload = bytes(udp.payload) if Raw in udp else b""

        return {
            **schema,
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "payload_length": len(payload),
            "payload": payload.decode("utf-8", errors="ignore") if payload else None,
        }

    if ICMP in packet:
        icmp = packet[ICMP]

        return {
            **schema,
            "protocol": "ICMP",
            "type": icmp.type,
            "code": icmp.code,
        }

    return {
        **schema,
        "protocol": "UNKNOWN",
    }