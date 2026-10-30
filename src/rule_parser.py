"""Module Rule Parser & Validator.

Chuyển một dòng rule Snort thành Internal Rule Object thống nhất:

    action proto src_ip src_port dir dst_ip dst_port (opt1; opt2:value; ...)

Phân loại kết quả:
- valid        rule đúng cú pháp, mọi keyword trong phạm vi hỗ trợ
- invalid      sai cú pháp / sai kiểu dữ liệu / thiếu field bắt buộc (sid)
- unsupported  đúng cú pháp nhưng dùng action/protocol/keyword ngoài phạm vi

Không bao giờ raise ra ngoài: lỗi được ghi vào "status" và "reason".
Các key bắt đầu bằng "_" là dữ liệu đã biên dịch sẵn cho matcher
(ip_network, bytes), không ghi ra report.
"""

import ipaddress
import re


SUPPORTED_ACTIONS = ("alert",)
KNOWN_ACTIONS = ("alert", "log", "pass", "drop", "reject", "sdrop", "activate", "dynamic")
SUPPORTED_PROTOCOLS = ("tcp", "udp", "ip")
KNOWN_PROTOCOLS = ("tcp", "udp", "ip", "icmp")
DIRECTIONS = ("->", "<>")

# keyword trong phạm vi bài tập
SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev", "classtype", "priority",
    "content", "nocase", "offset", "depth", "distance", "within",
    "flags", "dsize", "flow",
}
# keyword chỉ mang thông tin, không ảnh hưởng detection → chấp nhận và bỏ qua
INFORMATIONAL_KEYWORDS = {"reference", "metadata", "gid"}

FLOW_DIRECTIONS = {"to_server": "to_server", "from_client": "to_server",
                   "to_client": "to_client", "from_server": "to_client"}
FLOW_STATES = ("established", "not_established", "stateless")
TCP_FLAG_CHARS = "FSRPAUCE0"
LEGACY_FLAG_CHARS = {"1": "C", "2": "E"}   # Snort 2: 1=CWR, 2=ECE

# giá trị mặc định cho các biến hay gặp trong bộ rule Snort community;
# ghi đè được bằng "variables" trong file cấu hình
DEFAULT_VARIABLES = {
    "HOME_NET": "any", "EXTERNAL_NET": "any",
    "HTTP_SERVERS": "any", "SMTP_SERVERS": "any", "DNS_SERVERS": "any",
    "SQL_SERVERS": "any", "TELNET_SERVERS": "any",
    "HTTP_PORTS": "[80,8000,8080,8888]", "SSH_PORTS": "22",
    "FTP_PORTS": "[21,2100,3535]", "ORACLE_PORTS": "1521",
}


class RuleInvalid(Exception):
    """Rule sai cú pháp/kiểu dữ liệu."""


class RuleUnsupported(Exception):
    """Rule đúng cú pháp nhưng ngoài phạm vi hỗ trợ."""


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _expand_var(value, variables):
    if not value.startswith("$"):
        return value
    name = value[1:]
    if name not in variables:
        raise RuleInvalid(f"undefined variable ${name}")
    return variables[name]


def _split_list(value):
    """'[a,b,c]' → ['a','b','c']; giá trị thường → [value]."""
    if value.startswith("["):
        if not value.endswith("]"):
            raise RuleInvalid(f"unterminated list {value!r}")
        items = [v.strip() for v in value[1:-1].split(",")]
        if not all(items):
            raise RuleInvalid(f"empty item in list {value!r}")
        return items
    return [value]


def parse_ip_spec(value, variables):
    """any | IPv4 | CIDR | [list] | !spec | $VAR → {"any", "negate", "nets"}."""
    negate = value.startswith("!")
    if negate:
        value = value[1:]
    value = _expand_var(value, variables)
    if value.startswith("!"):                    # biến tự chứa '!'
        negate, value = not negate, value[1:]
    if value == "any":
        if negate:
            raise RuleInvalid("'!any' never matches")
        return {"any": True, "negate": False, "nets": [], "_nets": []}

    nets = []
    for item in _split_list(value):
        item = _expand_var(item, variables)
        if item.startswith("!") or item.startswith("["):
            raise RuleUnsupported(f"nested/negated IP list item {item!r}")
        if item == "any":
            return {"any": True, "negate": False, "nets": [], "_nets": []}
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise RuleInvalid(f"invalid IP address {item!r}")
        if net.version != 4:
            raise RuleUnsupported(f"IPv6 address {item!r}")
        nets.append(net)
    return {"any": False, "negate": negate,
            "nets": [str(n) for n in nets], "_nets": nets}


def _parse_port_number(text):
    if not text.isdigit() or not 0 <= int(text) <= 65535:
        raise RuleInvalid(f"invalid port {text!r}")
    return int(text)


def parse_port_spec(value, variables):
    """any | 80 | 1:1024 | :1024 | 1024: | [80,443,8000:8080] | !spec → ranges."""
    negate = value.startswith("!")
    if negate:
        value = value[1:]
    value = _expand_var(value, variables)
    if value.startswith("!"):
        negate, value = not negate, value[1:]
    if value == "any":
        if negate:
            raise RuleInvalid("'!any' never matches")
        return {"any": True, "negate": False, "ranges": []}

    ranges = []
    for item in _split_list(value):
        item = _expand_var(item, variables)
        if item.startswith("!") or item.startswith("["):
            raise RuleUnsupported(f"nested/negated port list item {item!r}")
        if ":" in item:
            lo, _, hi = item.partition(":")
            lo = _parse_port_number(lo) if lo else 0
            hi = _parse_port_number(hi) if hi else 65535
            if lo > hi:
                raise RuleInvalid(f"invalid port range {item!r}")
        else:
            lo = hi = _parse_port_number(item)
        ranges.append([lo, hi])
    return {"any": False, "negate": negate, "ranges": ranges}


def _parse_header(header, rule, variables):
    # bỏ khoảng trắng trong list "[a, b]" để tách token bằng split()
    header = re.sub(r"\[[^\]]*\]", lambda m: m.group(0).replace(" ", ""), header)
    tokens = header.split()
    if len(tokens) != 7:
        raise RuleInvalid(f"header needs 7 fields, got {len(tokens)}")
    action, proto, src_ip, src_port, direction, dst_ip, dst_port = tokens

    action, proto = action.lower(), proto.lower()
    if action not in KNOWN_ACTIONS:
        raise RuleInvalid(f"unknown action {action!r}")
    if proto not in KNOWN_PROTOCOLS:
        raise RuleInvalid(f"unknown protocol {proto!r}")
    if direction not in DIRECTIONS:
        raise RuleInvalid(f"invalid direction {direction!r}")

    rule["action"] = action
    rule["protocol"] = proto
    rule["direction"] = direction
    rule["src_ip"] = parse_ip_spec(src_ip, variables)
    rule["dst_ip"] = parse_ip_spec(dst_ip, variables)
    rule["src_port"] = parse_port_spec(src_port, variables)
    rule["dst_port"] = parse_port_spec(dst_port, variables)

    # kiểm tra cú pháp header xong mới báo unsupported
    if action not in SUPPORTED_ACTIONS:
        raise RuleUnsupported(f"action {action!r}")
    if proto not in SUPPORTED_PROTOCOLS:
        raise RuleUnsupported(f"protocol {proto!r}")


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

def split_options(body):
    """Tách 'k1:v1; k2; k3:"a;b";' theo ';' nằm ngoài dấu nháy."""
    options, current, in_quote, escaped = [], "", False, False
    for ch in body:
        if escaped:
            current += ch
            escaped = False
        elif ch == "\\":
            current += ch
            escaped = True
        elif ch == '"':
            current += ch
            in_quote = not in_quote
        elif ch == ";" and not in_quote:
            if current.strip():
                options.append(current.strip())
            current = ""
        else:
            current += ch
    if in_quote:
        raise RuleInvalid("unterminated quoted string in options")
    if current.strip():
        options.append(current.strip())
    return options


def _unquote(value, keyword):
    value = value.strip()
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        raise RuleInvalid(f"{keyword} must be a quoted string")
    return value[1:-1]


def parse_content(value):
    """'"abc|0d 0a|def"' → bytes. Hỗ trợ |hex| và escape \\" \\; \\\\ \\:."""
    if value.strip().startswith("!"):
        raise RuleUnsupported("negated content")
    text = _unquote(value, "content")
    out, i = bytearray(), 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            out += text[i + 1].encode("latin-1", errors="replace")
            i += 2
        elif ch == "|":
            end = text.find("|", i + 1)
            if end < 0:
                raise RuleInvalid("unterminated |hex| in content")
            hex_text = text[i + 1:end].replace(" ", "")
            try:
                out += bytes.fromhex(hex_text)
            except ValueError:
                raise RuleInvalid(f"invalid hex in content: {hex_text!r}")
            i = end + 1
        else:
            out += ch.encode("utf-8")
            i += 1
    if not out:
        raise RuleInvalid("empty content")
    return bytes(out)


def _parse_int(value, keyword, minimum=None):
    try:
        number = int(value.strip())
    except (ValueError, AttributeError):
        raise RuleInvalid(f"{keyword} must be an integer, got {value!r}")
    if minimum is not None and number < minimum:
        raise RuleInvalid(f"{keyword} must be >= {minimum}, got {number}")
    return number


def parse_flags(value):
    """flags:[!|*|+]<FSRPAUCE0>[+|*|!][,<mask>] → {"bits", "modifier", "mask"}."""
    value = value.strip()
    bits_text, _, mask_text = value.partition(",")
    modifier = None
    for mod in "+*!":
        if bits_text.startswith(mod) or bits_text.endswith(mod):
            modifier = mod
            bits_text = bits_text.strip(mod)
            break

    def clean(text):
        text = "".join(LEGACY_FLAG_CHARS.get(c, c) for c in text.upper())
        bad = [c for c in text if c not in TCP_FLAG_CHARS]
        if bad:
            raise RuleInvalid(f"invalid TCP flag(s) {''.join(bad)!r}")
        return text

    bits, mask = clean(bits_text), clean(mask_text)
    if not bits:
        raise RuleInvalid("flags needs at least one flag")
    if "0" in bits and len(bits) > 1:
        raise RuleInvalid("flag '0' cannot be combined with other flags")
    return {"bits": bits, "modifier": modifier, "mask": mask}


def parse_dsize(value):
    """dsize: N | >N | <N | >=N | <=N | !N | N<>M → {"op", "value"} / {"op","min","max"}."""
    value = value.strip().replace(" ", "")
    if "<>" in value:
        lo, _, hi = value.partition("<>")
        lo, hi = _parse_int(lo, "dsize", 0), _parse_int(hi, "dsize", 0)
        if lo > hi:
            raise RuleInvalid(f"invalid dsize range {value!r}")
        return {"op": "<>", "min": lo, "max": hi}
    for op in (">=", "<=", ">", "<", "!", "="):
        if value.startswith(op):
            return {"op": op, "value": _parse_int(value[len(op):], "dsize", 0)}
    return {"op": "=", "value": _parse_int(value, "dsize", 0)}


def parse_flow(value):
    """flow:to_server,established → {"direction", "state"}."""
    flow = {"direction": None, "state": None}
    for item in (v.strip().lower() for v in value.split(",")):
        if item in FLOW_DIRECTIONS:
            if flow["direction"] and flow["direction"] != FLOW_DIRECTIONS[item]:
                raise RuleInvalid("flow has conflicting directions")
            flow["direction"] = FLOW_DIRECTIONS[item]
        elif item in FLOW_STATES:
            if flow["state"] and flow["state"] != item:
                raise RuleInvalid("flow has conflicting states")
            flow["state"] = item
        elif item in ("no_stream", "only_stream", "no_frag", "only_frag"):
            raise RuleUnsupported(f"flow option {item!r}")
        else:
            raise RuleInvalid(f"unknown flow option {item!r}")
    return flow


def _apply_content_modifier(rule, keyword, value):
    if not rule["contents"]:
        raise RuleInvalid(f"{keyword} without preceding content")
    content = rule["contents"][-1]
    if keyword == "nocase":
        if value is not None:
            raise RuleInvalid("nocase takes no value")
        content["nocase"] = True
        return
    if content[keyword] is not None:
        raise RuleInvalid(f"duplicate {keyword} for content {content['pattern']!r}")
    minimum = {"offset": 0, "depth": 1, "within": 1, "distance": None}[keyword]
    content[keyword] = _parse_int(value, keyword, minimum)

    absolute = content["offset"] is not None or content["depth"] is not None
    relative = content["distance"] is not None or content["within"] is not None
    if absolute and relative:
        raise RuleInvalid("cannot mix offset/depth with distance/within on one content")
    size = len(content["_bytes"])
    if keyword in ("depth", "within") and content[keyword] < size:
        raise RuleInvalid(f"{keyword} {content[keyword]} smaller than content length {size}")


def _parse_options(body, rule):
    unsupported = []
    for option in split_options(body):
        keyword, colon, value = option.partition(":")
        keyword = keyword.strip().lower()
        value = value if colon else None

        if keyword in INFORMATIONAL_KEYWORDS:
            continue
        if keyword not in SUPPORTED_KEYWORDS:
            if not re.fullmatch(r"[a-z_][a-z0-9_.]*", keyword):
                raise RuleInvalid(f"malformed option {option!r}")
            unsupported.append(keyword)
            continue
        if keyword != "nocase" and value is None:
            raise RuleInvalid(f"{keyword} requires a value")

        if keyword == "msg":
            rule["msg"] = _unquote(value, "msg")
        elif keyword == "sid":
            rule["sid"] = _parse_int(value, "sid", 1)
        elif keyword == "rev":
            rule["rev"] = _parse_int(value, "rev", 1)
        elif keyword == "priority":
            rule["priority"] = _parse_int(value, "priority", 1)
        elif keyword == "classtype":
            rule["classtype"] = value.strip()
        elif keyword == "content":
            raw = parse_content(value)
            rule["contents"].append({
                "pattern": raw.decode("latin-1"), "nocase": False,
                "offset": None, "depth": None, "distance": None, "within": None,
                "_bytes": raw,
            })
        elif keyword in ("nocase", "offset", "depth", "distance", "within"):
            _apply_content_modifier(rule, keyword, value)
        elif keyword == "flags":
            rule["flags"] = parse_flags(value)
        elif keyword == "dsize":
            rule["dsize"] = parse_dsize(value)
        elif keyword == "flow":
            rule["flow"] = parse_flow(value)
    return unsupported


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def new_rule(text="", source=None, line=None):
    return {
        "status": None, "reason": None,
        "file": source, "line": line, "text": text,
        "action": None, "protocol": None, "direction": None,
        "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None,
        "msg": None, "sid": None, "rev": 1, "classtype": None, "priority": None,
        "contents": [], "flags": None, "dsize": None, "flow": None,
    }


def parse_rule(text, source=None, line=None, variables=None):
    """Rule text → Internal Rule Object (luôn trả về dict, không raise)."""
    variables = {**DEFAULT_VARIABLES, **(variables or {})}
    rule = new_rule(text, source, line)
    try:
        open_idx, close_idx = text.find("("), text.rfind(")")
        if open_idx < 0 or close_idx < open_idx:
            raise RuleInvalid("missing '( options )'")
        if text[close_idx + 1:].strip():
            raise RuleInvalid("unexpected text after ')'")

        header_error = None
        try:
            _parse_header(text[:open_idx], rule, variables)
        except RuleUnsupported as error:
            header_error = error            # vẫn parse options để bắt lỗi invalid
        unsupported = _parse_options(text[open_idx + 1:close_idx], rule)

        if rule["sid"] is None:
            raise RuleInvalid("missing sid")
        if rule["flags"] and rule["protocol"] != "tcp":
            raise RuleInvalid("flags requires protocol tcp")
        if header_error:
            raise header_error
        if unsupported:
            raise RuleUnsupported("keyword(s) " + ", ".join(unsupported))
        rule["status"] = "valid"
    except RuleUnsupported as error:
        rule["status"] = "unsupported"
        rule["reason"] = f"unsupported {error}"
    except RuleInvalid as error:
        rule["status"] = "invalid"
        rule["reason"] = str(error)
    except Exception as error:               # lưới an toàn cuối cùng
        rule["status"] = "invalid"
        rule["reason"] = f"parser error: {error}"
    return rule


def public_view(rule):
    """Bản JSON-friendly của rule: bỏ các key '_' đã biên dịch."""
    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if not k.startswith("_")}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    return strip(rule)
