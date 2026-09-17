from scapy.all import IP, IPv6 

# Normalized schema: mọi packet đều trả đúng các key này (thiếu thì None)
def parse_network(packet):
    schema = {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "ttl": None,
        "hop_limit": None,
    }

    if IP in packet:
        ip = packet[IP]
        return {
            **schema,
            "protocol": "IPv4",
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": ip.ttl,
        }

    if IPv6 in packet:
        ipv6 = packet[IPv6]
        return {
            **schema,
            "protocol": "IPv6",
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "hop_limit": ipv6.hlim,
        }

    return {
        **schema,
        "protocol": "UNKNOWN",
    }