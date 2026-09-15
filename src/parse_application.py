from scapy.all import DNS, DNSQR, Raw, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

def parse_application(packet):
    def safe_decode(value):
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    def _get_attr(layer, name):
        return safe_decode(getattr(layer, name, None))

    def _split_header(line):
        return line.split(":", 1)[1].strip()

    def _parse_headers(lines, keys):
        result = {}
        for line in lines:
            lower = line.lower()
            for key in keys:
                if lower.startswith(key + ":"):
                    result[key.replace("-", "_")] = _split_header(line)
                    break
        return result

    HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                    b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

    try:
        # 1. DNS
        if DNS in packet:
            dns = packet[DNS]
            result = {
                "protocol": "DNS", "id": dns.id, "qr": dns.qr,
                "opcode": dns.opcode, "rcode": dns.rcode,
                "question_count": dns.qdcount, "answer_count": dns.ancount,
            }
            if DNSQR in packet:
                q = packet[DNSQR]
                result["query_name"] = safe_decode(q.qname)
                result["query_type"] = q.qtype
            return result

        # 2. HTTP Request (Scapy parsed)
        if HTTPRequest in packet:
            h = packet[HTTPRequest]
            return {
                "protocol": "HTTP", "type": "request",
                "method": _get_attr(h, "Method"),
                "host": _get_attr(h, "Host"),
                "path": _get_attr(h, "Path"),
                "version": _get_attr(h, "Http_Version"),
                "user_agent": _get_attr(h, "User_Agent"),
            }

        # 3. HTTP Response (Scapy parsed)
        if HTTPResponse in packet:
            h = packet[HTTPResponse]
            return {
                "protocol": "HTTP", "type": "response",
                "version": _get_attr(h, "Http_Version"),
                "status_code": _get_attr(h, "Status_Code"),
                "reason": _get_attr(h, "Reason_Phrase"),
            }

        # 4. Payload-based detection
        if Raw in packet:
            payload = bytes(packet[Raw].load)

            # HTTP Request from raw payload
            if any(payload.startswith(m) for m in HTTP_METHODS):
                lines = payload.decode("utf-8", errors="ignore").split("\r\n")
                result = {"protocol": "HTTP", "type": "request",
                          "method": None, "host": None, "path": None, "version": None}
                if lines:
                    parts = lines[0].split(" ")
                    if len(parts) >= 3:
                        result["method"], result["path"], result["version"] = parts[0], parts[1], parts[2]
                result.update(_parse_headers(lines[1:], ["host", "user-agent", "content-type", "content-length"]))
                return result

            # HTTP Response from raw payload
            if payload.startswith(b"HTTP/"):
                lines = payload.decode("utf-8", errors="ignore").split("\r\n")
                result = {"protocol": "HTTP", "type": "response",
                          "version": None, "status_code": None, "reason": None}
                if lines:
                    parts = lines[0].split(" ", 2)
                    if len(parts) >= 1: result["version"] = parts[0]
                    if len(parts) >= 2: result["status_code"] = parts[1]
                    if len(parts) >= 3: result["reason"] = parts[2]
                result.update(_parse_headers(lines[1:], ["content-type", "content-length", "server"]))
                return result

        # 5. Port-based hint (fallback)
        if TCP in packet:
            tcp = packet[TCP]
            http_ports = (80, 8000, 8080, 8888)
            if tcp.sport in http_ports or tcp.dport in http_ports:
                return {"protocol": "HTTP", "type": "UNKNOWN",
                        "method": None, "host": None, "path": None}

        if UDP in packet:
            udp = packet[UDP]
            if udp.sport == 53 or udp.dport == 53:
                return {"protocol": "DNS"}

        # 6. Unknown
        return {"protocol": "UNKNOWN"}

    except Exception as error:
        return {"protocol": "UNKNOWN", "parse_error": str(error)}
