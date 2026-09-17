from scapy.all import DNS, DNSQR, Raw, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

def parse_application(packet):
    schema = {
        "protocol": None,
        "type": None,
        # HTTP request
        "method": None,
        "host": None,
        "path": None,
        "version": None,
        "user_agent": None,
        # HTTP response
        "status_code": None,
        "reason": None,
        "body_length": None,
        "body": None,
        # HTTP headers
        "date": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "content_encoding": None,
        "connection": None,
        "keep_alive": None,
        "cache_control": None,
        "location": None,
        "set_cookie": None,
        # DNS
        "id": None,
        "qr": None,
        "opcode": None,
        "rcode": None,
        "question_count": None,
        "answer_count": None,
        "answers": None,
        "query_name": None,
        "query_type": None,
        # SMTP
        "smtp_command": None,
        "smtp_argument": None,
        "smtp_status": None,
        "smtp_message": None,
        # error
        "parse_error": None,
    }

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

    def __http_body(payload):
        if payload:
            sep = b"\r\n\r\n" if b"\r\n\r\n" in payload else b"\n\n"
            if sep in payload:
                body = payload.split(sep, 1)[1]
                return len(body), body.decode("utf-8", errors="ignore")
        return 0, None

    HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                    b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

    REQUEST_HEADER_KEYS = ("host", "user-agent", "content-type", "content-length")

    RESPONSE_HEADER_KEYS = ("date", "server", "content-type", "content-length",
                            "connection", "keep-alive", "cache-control",
                            "location", "set-cookie", "content-encoding")

    SMTP_PORTS = (25, 465, 587)

    SMTP_COMMANDS = ("HELO", "EHLO", "MAIL", "RCPT", "DATA", "QUIT",
                     "RSET", "NOOP", "VRFY", "EXPN", "STARTTLS", "AUTH", "BDAT")

    try:
        # 1. DNS
        if DNS in packet:
            dns = packet[DNS]
            result = {
                **schema,
                "protocol": "DNS",
                "type": "query" if dns.qr == 0 else "response",
                "id": dns.id, "qr": dns.qr,
                "opcode": dns.opcode, "rcode": dns.rcode,
                "question_count": dns.qdcount, "answer_count": dns.ancount,
            }
            if DNSQR in packet:
                q = packet[DNSQR]
                result["query_name"] = safe_decode(q.qname)
                result["query_type"] = q.qtype

            # DNS Response: parse cac answer (neu co)
            if result["qr"] == 1 and result["answer_count"] > 0:
                answers = []
                for answer in dns.an:
                    answers.append({
                        "name": safe_decode(getattr(answer, "rrname", None)),
                        "type": getattr(answer, "type", None),
                        "ttl": getattr(answer, "ttl", None),
                        "data": safe_decode(getattr(answer, "rdata", None)),
                    })
                result["answers"] = answers
            return result

        # 2. HTTP Request (Scapy parsed)
        if HTTPRequest in packet:
            h = packet[HTTPRequest]
            body_len, body = __http_body(bytes(packet[TCP].payload))
            text = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
            return {
                **schema,
                "protocol": "HTTP", "type": "request",
                "method": _get_attr(h, "Method"),
                "host": _get_attr(h, "Host"),
                "path": _get_attr(h, "Path"),
                "version": _get_attr(h, "Http_Version"),
                "user_agent": _get_attr(h, "User_Agent"),
                "body_length": body_len,
                "body": body,
                **_parse_headers(lines[1:], REQUEST_HEADER_KEYS),
            }

        # 3. HTTP Response (Scapy parsed)
        if HTTPResponse in packet:
            h = packet[HTTPResponse]
            body_len, body = __http_body(bytes(packet[TCP].payload))
            text = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
            return {
                **schema,
                "protocol": "HTTP", "type": "response",
                "version": _get_attr(h, "Http_Version"),
                "status_code": _get_attr(h, "Status_Code"),
                "reason": _get_attr(h, "Reason_Phrase"),
                "body_length": body_len,
                "body": body,
                **_parse_headers(lines[1:], RESPONSE_HEADER_KEYS),
            }

        # 4. Payload-based detection
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            text = payload.decode("utf-8", errors="ignore")

            # HTTP Request from raw payload
            if any(payload.startswith(m) for m in HTTP_METHODS):
                lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
                result = {
                    **schema,
                    "protocol": "HTTP", "type": "request",
                    "method": None, "host": None, "path": None, "version": None,
                }
                if lines:
                    parts = lines[0].split(" ")
                    if len(parts) >= 3:
                        result["method"], result["path"], result["version"] = parts[0], parts[1], parts[2]
                result.update(_parse_headers(lines[1:], REQUEST_HEADER_KEYS))
                result["body_length"], result["body"] = __http_body(payload)
                return result

            # HTTP Response from raw payload
            if payload.startswith(b"HTTP/"):
                lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
                result = {
                    **schema,
                    "protocol": "HTTP", "type": "response",
                    "version": None, "status_code": None, "reason": None,
                }
                if lines:
                    parts = lines[0].split(" ", 2)
                    if len(parts) >= 1: result["version"] = parts[0]
                    if len(parts) >= 2: result["status_code"] = parts[1]
                    if len(parts) >= 3: result["reason"] = parts[2]
                result.update(_parse_headers(lines[1:], RESPONSE_HEADER_KEYS))
                result["body_length"], result["body"] = __http_body(payload)
                return result

        # 5. SMTP (port 25/465/587)
        if TCP in packet:
            tcp = packet[TCP]
            if tcp.sport in SMTP_PORTS or tcp.dport in SMTP_PORTS:
                if Raw in packet:
                    line = bytes(packet[Raw].load).split(b"\r\n", 1)[0]
                    line_str = line.decode("utf-8", errors="ignore")

                    # SMTP response: "250 mail.webertest.net" hoac "220-..."
                    if len(line_str) >= 3 and line_str[:3].isdigit():
                        status = line_str[:3]
                        if len(line_str) > 4 and line_str[3] in (" ", "-"):
                            return {
                                **schema,
                                "protocol": "SMTP", "type": "response",
                                "smtp_status": status,
                                "smtp_message": line_str[4:],
                            }
                        return {
                            **schema,
                            "protocol": "SMTP", "type": "response",
                            "smtp_status": status,
                        }

                    # SMTP command: "HELO localhost", "MAIL FROM: <>", ...
                    keyword = line_str.split(" ", 1)[0].upper()
                    if keyword in SMTP_COMMANDS:
                        argument = line_str[len(keyword):].strip()
                        return {
                            **schema,
                            "protocol": "SMTP", "type": "command",
                            "smtp_command": keyword,
                            "smtp_argument": argument if argument else None,
                        }

                    return {
                        **schema,
                        "protocol": "SMTP", "type": "UNKNOWN",
                    }

                return {
                    **schema,
                    "protocol": "SMTP", "type": "UNKNOWN",
                }

        # 6. Port-based hint (fallback)
        if TCP in packet:
            tcp = packet[TCP]
            http_ports = (80, 8000, 8080, 8888)
            if tcp.sport in http_ports or tcp.dport in http_ports:
                return {
                    **schema,
                    "protocol": "HTTP", "type": "UNKNOWN",
                }

        if UDP in packet:
            udp = packet[UDP]
            if udp.sport == 53 or udp.dport == 53:
                return {
                    **schema,
                    "protocol": "DNS",
                }

        # 7. Unknown
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