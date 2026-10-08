from scapy.all import IP, IPv6 

def parse_network(packet):
    schema = {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "ttl": None,
        "hop_limit": None,
        "ip_length": None,
    }

    try:
        if IP in packet:
            ip = packet[IP]
            return {
                **schema,
                "protocol": "IPv4",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "ip_length": ip.len,
            }

        if IPv6 in packet:
            ipv6 = packet[IPv6]
            return {
                **schema,
                "protocol": "IPv6",
                "src_ip": ipv6.src,
                "dst_ip": ipv6.dst,
                "hop_limit": ipv6.hlim,
                "ip_length": ipv6.plen,
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