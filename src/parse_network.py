from scapy.all import IP, IPv6 

def parse_network(packet):
    if IP in packet: 
        ip = packet[IP]

        return {
            "protocol": "IPv4",
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "ttl": ip.ttl
        }
    elif IPv6 in packet:
        ipv6 = packet[IPv6]

        return {
            "protocol": "IPv6", 
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "hop_limit": ipv6.hlim
        }

    return {
        "protocol": "UNKNOWN"
    }