"""Module Rule Matching Engine.

Trả lời: một rule có thỏa mãn normalized event + flow context hay không.
Thứ tự kiểm tra từ rẻ đến đắt, dừng ngay khi một bước không thỏa:

    header → flow → flags → dsize → content

Kết quả luôn là dict:
    {"sid", "result": "MATCH" | "NO_MATCH",
     "stage": bước bị loại (None nếu MATCH), "reason", "matched": {...}}

Matcher không in cảnh báo; Detection Event do module detection sinh ra.
"""

import base64
import binascii
import ipaddress


def _result(rule, ok, stage=None, reason=None, matched=None):
    return {"sid": rule["sid"], "result": "MATCH" if ok else "NO_MATCH",
            "stage": None if ok else stage, "reason": reason,
            "matched": matched or {}}


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _ip_match(spec, value):
    if spec["any"]:
        return True
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    inside = any(address.version == net.version and address in net
                 for net in spec["_nets"])
    return inside != spec["negate"]


def _port_match(spec, port):
    if spec["any"]:
        return True
    if not isinstance(port, int):
        return False
    inside = any(lo <= port <= hi for lo, hi in spec["ranges"])
    return inside != spec["negate"]


def _endpoints(event):
    """(src_ip, src_port, dst_ip, dst_port) — ưu tiên IP đã chuẩn hóa."""
    network = event.get("network") or {}
    transport = event.get("transport") or {}
    norm = (event.get("preprocess") or {}).get("normalized") or {}
    return (norm.get("src_ip") or network.get("src_ip"), transport.get("src_port"),
            norm.get("dst_ip") or network.get("dst_ip"), transport.get("dst_port"))


def match_header(rule, event):
    """Trả về (ok, reason). Với '<>' cho phép khớp theo chiều ngược lại."""
    network = event.get("network") or {}
    transport = event.get("transport") or {}
    proto = rule["protocol"]
    if proto == "ip":
        if network.get("protocol") != "IPv4":
            return False, "protocol ip requires IPv4 packet"
    elif str(transport.get("protocol") or "").lower() != proto:
        return False, f"protocol {transport.get('protocol')} != {proto}"

    src_ip, src_port, dst_ip, dst_port = _endpoints(event)
    use_ports = proto != "ip"            # rule ip bỏ qua port

    def side(ip_spec, port_spec, ip, port):
        return _ip_match(ip_spec, ip) and (not use_ports or _port_match(port_spec, port))

    forward = (side(rule["src_ip"], rule["src_port"], src_ip, src_port)
               and side(rule["dst_ip"], rule["dst_port"], dst_ip, dst_port))
    if forward:
        return True, None
    if rule["direction"] == "<>":
        backward = (side(rule["src_ip"], rule["src_port"], dst_ip, dst_port)
                    and side(rule["dst_ip"], rule["dst_port"], src_ip, src_port))
        if backward:
            return True, None
    return False, "address/port mismatch"


# ---------------------------------------------------------------------------
# Flow / Packet
# ---------------------------------------------------------------------------

def match_flow(rule, flow_ctx):
    flow = rule["flow"]
    if not flow:
        return True, None
    ctx = flow_ctx or {}
    if flow["direction"] == "to_server" and not ctx.get("to_server"):
        return False, "flow is not to_server"
    if flow["direction"] == "to_client" and not ctx.get("to_client"):
        return False, "flow is not to_client"
    if flow["state"] == "established" and not ctx.get("established"):
        return False, f"flow not established (state={ctx.get('state')})"
    if flow["state"] == "not_established" and ctx.get("established"):
        return False, "flow is established"
    return True, None


def match_flags(rule, event):
    spec = rule["flags"]
    if not spec:
        return True, None
    transport = event.get("transport") or {}
    if transport.get("protocol") != "TCP":
        return False, "flags on non-TCP packet"
    packet = set(str(transport.get("flags") or "")) - set(spec["mask"])
    packet &= set("FSRPAUCE")
    wanted = set(spec["bits"]) - {"0"}
    mod = spec["modifier"]
    if spec["bits"] == "0":
        ok = not packet
    elif mod == "+":
        ok = wanted <= packet
    elif mod == "*":
        ok = bool(wanted & packet)
    elif mod == "!":
        ok = not (wanted & packet)
    else:
        ok = packet == wanted
    flags_text = "".join(sorted(packet)) or "0"
    return ok, None if ok else f"flags {flags_text} do not satisfy {spec['bits']}{mod or ''}"


def match_dsize(rule, event):
    spec = rule["dsize"]
    if not spec:
        return True, None
    size = (event.get("transport") or {}).get("payload_length") or 0
    op = spec["op"]
    if op == "<>":
        ok = spec["min"] <= size <= spec["max"]
    else:
        value = spec["value"]
        ok = {"=": size == value, "!": size != value, ">": size > value,
              "<": size < value, ">=": size >= value, "<=": size <= value}[op]
    return ok, None if ok else f"dsize {size} does not satisfy {op}{spec.get('value', '')}"


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

def content_buffers(event):
    """Các vùng dữ liệu để tìm content: payload gốc, sau đó dữ liệu đã decode."""
    buffers = []
    payload_b64 = (event.get("transport") or {}).get("payload_b64")
    if payload_b64:
        try:
            buffers.append(("payload", base64.b64decode(payload_b64)))
        except (binascii.Error, ValueError):
            pass
    decoder = event.get("decoder") or {}
    for field in ("uri_decoded", "text_decoded", "body_decoded"):
        if decoder.get(field):
            buffers.append((field, decoder[field].encode("utf-8")))
    return buffers


def _search(data, contents, index, prev_end):
    """Tìm contents[index:] trong data, có backtracking cho relative match.

    Trả về list vị trí match hoặc None.
    - offset/depth: tính từ đầu buffer
    - distance/within: tính từ cuối match trước (prev_end); within giới hạn
      vùng tìm sau điểm bắt đầu (như depth nhưng tương đối)
    """
    if index == len(contents):
        return []
    content = contents[index]
    pattern = content["_bytes"]
    haystack = data
    if content["nocase"]:
        pattern, haystack = pattern.lower(), data.lower()

    if content["distance"] is not None or content["within"] is not None:
        start = prev_end + (content["distance"] or 0)
        limit = content["within"]
    else:
        start = content["offset"] or 0
        limit = content["depth"]
    start = max(start, 0)
    end = len(haystack) if limit is None else min(len(haystack), start + limit)

    pos = haystack.find(pattern, start, end)
    while pos >= 0:
        rest = _search(data, contents, index + 1, pos + len(pattern))
        if rest is not None:
            return [pos] + rest
        pos = haystack.find(pattern, pos + 1, end)
    return None


def match_content(rule, event):
    contents = rule["contents"]
    if not contents:
        return True, None, []
    for name, data in content_buffers(event):
        positions = _search(data, contents, 0, 0)
        if positions is not None:
            matched = [{"content": c["pattern"], "buffer": name, "offset": pos,
                        "nocase": c["nocase"]}
                       for c, pos in zip(contents, positions)]
            return True, None, matched
    return False, "content not found", []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def match(rule, event, flow_ctx):
    try:
        ok, reason = match_header(rule, event)
        if not ok:
            return _result(rule, False, "header", reason)
        ok, reason = match_flow(rule, flow_ctx)
        if not ok:
            return _result(rule, False, "flow", reason)
        ok, reason = match_flags(rule, event)
        if not ok:
            return _result(rule, False, "flags", reason)
        ok, reason = match_dsize(rule, event)
        if not ok:
            return _result(rule, False, "dsize", reason)
        ok, reason, contents = match_content(rule, event)
        if not ok:
            return _result(rule, False, "content", reason)
    except Exception as error:                # một rule lỗi không làm dừng engine
        return _result(rule, False, "error", f"matcher error: {error}")

    matched = {"contents": contents}
    if rule["flow"]:
        matched["flow"] = {k: v for k, v in rule["flow"].items() if v}
    if rule["flags"]:
        matched["flags"] = (event.get("transport") or {}).get("flags")
    if rule["dsize"]:
        matched["dsize"] = (event.get("transport") or {}).get("payload_length")
    return _result(rule, True, matched=matched)
