"""Module Preprocessor.

Kiểm tra và chuẩn hóa dữ liệu để module IDS phía sau nhận biểu diễn nhất quán:
- Validation: field bắt buộc, port/range hợp lệ, timestamp, protocol
  → preprocess_status = valid | partial | invalid
- Normalization: protocol name, IP/domain, HTTP header name, URI/path, timestamp
- Missing/unsupported data: giá trị nhất quán null/[], đánh dấu hoặc bỏ qua
  theo cấu hình (processing_action = continue | skip)
- Metadata: reason khi cần
"""

import ipaddress
import re
from urllib.parse import unquote

PREPROCESS_SECTION_SCHEMA = {
    "preprocess_status": None,     # valid | partial | invalid
    "processing_action": None,     # continue | skip
    "reason": None,
    "normalized": {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "host": None,
        "path": None,
        "header_names": [],        # list → thiếu dữ liệu dùng []
        "timestamp": None,
    },
}


def new_section():
    """Section preprocess rỗng cho mỗi event — copy cả nested normalized."""
    section = {**PREPROCESS_SECTION_SCHEMA}
    section["normalized"] = dict(PREPROCESS_SECTION_SCHEMA["normalized"])
    return section


KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "DNS", "SMTP", "TLS", "UNKNOWN"}
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$")


def _norm_ip(value):
    try:
        return ipaddress.ip_address(str(value)).compressed
    except ValueError:
        return None


def _norm_host(value):
    host = value.strip().lower()
    if host.count(":") == 1:            # bỏ port nếu có (example.com:8080)
        host = host.split(":")[0]
    host = host.rstrip(".")
    if not host or not HOST_RE.match(host):
        return None
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _norm_path(value):
    if not value:
        return None
    path = unquote(value.split("?")[0])
    path = re.sub(r"/{2,}", "/", path)
    parts = [p for p in path.split("/") if p not in ("", ".")]
    return "/" + "/".join(parts)


def _norm_header_names(app):
    keys = ("host", "user_agent", "content_type", "content_length", "date",
            "server", "connection", "location", "content_encoding",
            "cache_control", "keep_alive", "set_cookie")
    return sorted(k for k in keys if app.get(k) is not None)


def apply(event):
    section = event["preprocess"]
    network = event.get("network") or {}
    transport = event.get("transport") or {}
    app = event.get("application") or {}
    reasons = []
    hard_error = False

    try:
        # --- validation ---
        ts = event.get("timestamp")
        if not isinstance(ts, (int, float)):
            reasons.append(f"timestamp not numeric: {ts!r}")
            hard_error = True
        if network.get("protocol") not in ("IPv4", "IPv6", "UNKNOWN", None):
            reasons.append(f"invalid network protocol: {network.get('protocol')!r}")
            hard_error = True
        for name in ("src_port", "dst_port"):
            port = transport.get(name)
            if port is not None and not (isinstance(port, int) and 0 <= port <= 65535):
                reasons.append(f"invalid {name}: {port!r}")
                hard_error = True
        for name in ("src_ip", "dst_ip"):
            ip = network.get(name)
            if ip is not None and _norm_ip(ip) is None:
                reasons.append(f"invalid {name}: {ip!r}")
                hard_error = True
        tproto = transport.get("protocol")
        if tproto is not None and tproto not in KNOWN_PROTOCOLS:
            reasons.append(f"unknown transport protocol: {tproto!r}")
            hard_error = True

        # --- missing/unsupported: partial chứ không invalid ---
        if network.get("src_ip") is None and network.get("protocol") != "UNKNOWN":
            reasons.append("missing network address")
        if app.get("protocol") == "UNKNOWN":
            reasons.append("application protocol unknown")

        # --- normalization ---
        norm = section["normalized"]
        norm["protocol"] = (tproto or network.get("protocol") or "UNKNOWN").upper()
        norm["src_ip"] = _norm_ip(network.get("src_ip"))
        norm["dst_ip"] = _norm_ip(network.get("dst_ip"))
        host = app.get("host") or app.get("query_name")
        norm["host"] = _norm_host(host) if host else None
        if host and norm["host"] is None:
            reasons.append(f"invalid host: {host!r}")
        norm["path"] = _norm_path(app.get("path"))
        norm["header_names"] = _norm_header_names(app)
        norm["timestamp"] = float(ts) if isinstance(ts, (int, float)) else None

        if hard_error:
            section["preprocess_status"] = "invalid"
            section["processing_action"] = "skip"
            section["reason"] = "; ".join(reasons)
        elif reasons:
            section["preprocess_status"] = "partial"
            section["processing_action"] = "continue"
            section["reason"] = "; ".join(reasons)
        else:
            section["preprocess_status"] = "valid"
            section["processing_action"] = "continue"
    except Exception as error:
        section["preprocess_status"] = "invalid"
        section["processing_action"] = "skip"
        section["reason"] = f"preprocess error: {error}"

    return event
