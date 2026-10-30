from scapy.all import TCP, UDP, ICMP, Padding
import base64


def _payload_bytes(layer):
    """Bytes payload thật của TCP/UDP.

    Không dùng `Raw in layer` vì Scapy đã tách HTTP/DNS thành layer riêng
    (không còn Raw) → payload bị mất. Cắt bỏ Padding Ethernet ở cuối frame.
    """
    data = bytes(layer.payload)
    pad = layer.getlayer(Padding)
    if pad is not None and pad.load:
        data = data[:len(data) - len(pad.load)]
    return data

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
        "payload_b64": None,
    }

    try:
        if TCP in packet:
            tcp = packet[TCP]
            payload = _payload_bytes(tcp)

            return {
                **schema,
                "protocol": "TCP",
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "flags": str(tcp.flags),
                "seq": tcp.seq,
                "ack": tcp.ack,
                "payload_length": len(payload),
                "payload_b64": base64.b64encode(payload).decode("ascii") if payload else None,
            }

        if UDP in packet:
            udp = packet[UDP]
            payload = _payload_bytes(udp)

            return {
                **schema,
                "protocol": "UDP",
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "length": udp.len,
                "payload_length": len(payload),
                "payload_b64": base64.b64encode(payload).decode("ascii") if payload else None,
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

    except Exception as error:
        return {
            **schema,
            "protocol": "UNKNOWN",
            "parse_error": str(error),
        }