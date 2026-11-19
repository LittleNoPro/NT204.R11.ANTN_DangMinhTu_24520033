"""Module Alert Manager.

Nhận Detection Event từ Core Engine và chuyển thành Alert Object thống nhất cho
người vận hành:
- kiểm tra trường bắt buộc; event hỏng bị từ chối kèm lý do, không làm dừng IDS
- sinh alert_id duy nhất, chuẩn hóa timestamp/IP/port/protocol
- ánh xạ priority của rule sang severity theo cấu hình (alert.severity_map)

Core Engine chỉ phát Detection Event; mọi quyết định về cảnh báo nằm ở đây.
"""

import ipaddress
from datetime import datetime, timezone

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")   # nặng → nhẹ

ALERT_SCHEMA = {
    "alert_id": None,
    "timestamp": None,              # epoch giây (float), dùng để truy vấn
    "time": None,                   # ISO 8601 UTC, để đọc
    "sid": None, "rev": None, "msg": None,
    "severity": None, "priority": None, "classtype": None,
    "protocol": None,               # TCP | UDP | ICMP | ...
    "application_protocol": None,   # HTTP | DNS | SMTP | null
    "src_ip": None, "src_port": None,
    "dst_ip": None, "dst_port": None,
    "flow_id": None, "packet_id": None,
    "status": "ok",                 # ok | partial (trường phụ sai, đã bỏ)
    "reason": None,                 # lý do khi partial
}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _timestamp(value):
    """Epoch (số) hoặc chuỗi ISO 8601 → epoch float. Sai định dạng → None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def iso_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AlertManager:
    def __init__(self, config, next_id=1):
        self.severity_map = config["severity_map"]
        self._next_id = next_id

    def severity(self, priority):
        """priority → severity. Mỗi khóa trong map là đầu một khoảng: với map
        {1, 2, 3, 4}, priority 7 thuộc khoảng "4 trở lên". Thiếu priority → mức
        của khóa lớn nhất (nhẹ nhất đã cấu hình)."""
        keys = sorted(self.severity_map)
        if priority is None:
            return self.severity_map[keys[-1]]
        below = [k for k in keys if k <= priority]
        return self.severity_map[below[-1] if below else keys[0]]

    def build(self, detection):
        """Detection Event → (alert, None), hoặc (None, lý do) nếu bị từ chối."""
        if not isinstance(detection, dict):
            return None, "detection event không phải object"

        timestamp = _timestamp(detection.get("timestamp"))
        if timestamp is None:
            return None, f"timestamp thiếu hoặc sai: {detection.get('timestamp')!r}"
        sid = detection.get("sid")
        if not _is_int(sid) or sid <= 0:
            return None, f"sid thiếu hoặc sai: {sid!r}"
        src_ip, dst_ip = _ip(detection.get("src_ip")), _ip(detection.get("dst_ip"))
        if src_ip is None or dst_ip is None:
            return None, (f"IP thiếu hoặc sai: src_ip={detection.get('src_ip')!r}, "
                          f"dst_ip={detection.get('dst_ip')!r}")
        protocol = detection.get("protocol")
        if not isinstance(protocol, str) or not protocol.strip():
            return None, f"protocol thiếu hoặc sai: {protocol!r}"

        # trường phụ: giá trị sai được bỏ (null) và ghi lý do, alert vẫn tạo
        problems = []

        def optional(name, valid):
            value = detection.get(name)
            if value is None or valid(value):
                return value
            problems.append(f"{name}={value!r}")
            return None

        priority = optional("priority", lambda v: _is_int(v) and v > 0)
        alert = {
            **ALERT_SCHEMA,
            "alert_id": f"A{self._next_id:06d}",
            "timestamp": timestamp,
            "time": iso_time(timestamp),
            "sid": sid,
            "rev": optional("rev", lambda v: _is_int(v) and v > 0) or 1,
            "msg": optional("msg", lambda v: isinstance(v, str)) or f"sid:{sid}",
            "severity": self.severity(priority),
            "priority": priority,
            "classtype": optional("classtype", lambda v: isinstance(v, str)),
            "protocol": protocol.strip().upper(),
            "application_protocol": optional("application_protocol", lambda v: isinstance(v, str)),
            "src_ip": src_ip,
            "src_port": optional("src_port", lambda v: _is_int(v) and 0 <= v <= 65535),
            "dst_ip": dst_ip,
            "dst_port": optional("dst_port", lambda v: _is_int(v) and 0 <= v <= 65535),
            "flow_id": optional("flow_id", lambda v: isinstance(v, str)),
            "packet_id": optional("packet_id", _is_int),
        }
        if problems:
            alert["status"] = "partial"
            alert["reason"] = "bỏ trường sai: " + ", ".join(problems)
        self._next_id += 1
        return alert, None
