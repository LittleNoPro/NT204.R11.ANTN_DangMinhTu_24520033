"""Module Alert Manager.

Nhận Detection Event từ Core Engine và chuyển thành Alert Object thống nhất cho
người vận hành:
- kiểm tra trường bắt buộc; event hỏng bị từ chối kèm lý do, không làm dừng IDS
- sinh alert_id duy nhất, chuẩn hóa timestamp/IP/port/protocol
- ánh xạ priority của rule sang severity theo cấu hình (alert.severity_map)
- lọc: bỏ alert dưới alert.min_severity hoặc khớp một mục alert.suppress
  (theo sid, src_ip, dst_ip, protocol — giống suppress/threshold của Snort)
- gom nhóm: Detection Event lặp lại cùng (sid, src_ip, dst_ip) trong
  alert.aggregation.window giây được gộp vào một alert (count, first_seen,
  last_seen) để hạn chế alert flooding

Core Engine chỉ phát Detection Event; mọi quyết định về cảnh báo nằm ở đây.
"""

import ipaddress
from collections import Counter
from datetime import datetime, timezone

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")   # nặng → nhẹ
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

ALERT_SCHEMA = {
    "alert_id": None,
    "first_seen": None,             # epoch giây của event đầu tiên trong nhóm
    "last_seen": None,              # epoch giây của event mới nhất trong nhóm
    "count": 1,                     # số Detection Event đã gộp vào alert này
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


def fast_line(alert):
    """Một dòng ngắn cho console/fast.log (giống alert_fast của Snort)."""
    def endpoint(ip, port):
        return ip if port is None else f"{ip}:{port}"
    return (f"{iso_time(alert['first_seen'])} [{alert['severity']}] {alert['alert_id']} "
            f"[sid:{alert['sid']}:{alert['rev']}] \"{alert['msg']}\" {alert['protocol']} "
            f"{endpoint(alert['src_ip'], alert['src_port'])} -> "
            f"{endpoint(alert['dst_ip'], alert['dst_port'])}")


class AlertManager:
    def __init__(self, config, next_id=1):
        self.severity_map = config["severity_map"]
        self.min_rank = SEVERITY_RANK[config["min_severity"]]
        self.suppress = config["suppress"]
        aggregation = config["aggregation"]
        self.window = aggregation["window"] if aggregation["enabled"] else None
        self.groups = {}                # (sid, src_ip, dst_ip) → alert đang mở
        self._next_sweep = None
        self._next_id = next_id
        self.stats = Counter()

    def process(self, detection):
        """Detection Event → (status, alert, reason).

        status:
        - alert       alert mới, được cấp alert_id
        - aggregated  gộp vào alert đang mở; trả về alert đó (cùng alert_id,
                      count/last_seen đã cập nhật)
        - filtered    bị lọc; không cấp alert_id
        - rejected    event hỏng; alert = None
        """
        self.stats["received"] += 1
        alert, reason = self.build(detection)
        if alert is None:
            status = "rejected"
        elif (reason := self.filter_reason(alert)):
            status = "filtered"
        else:
            status, alert = self._aggregate(alert)
        self.stats[status] += 1
        return status, alert, reason

    def _aggregate(self, alert):
        """Gộp vào nhóm đang mở nếu khoảng first_seen..last_seen sau khi thêm
        event vẫn không vượt window (so theo giờ packet, không theo đồng hồ máy);
        ngoài cửa sổ → mở alert mới."""
        now = alert["first_seen"]
        if self.window is not None:
            self._expire(now)
            key = (alert["sid"], alert["src_ip"], alert["dst_ip"])
            group = self.groups.get(key)
            if (group is not None
                    and max(group["last_seen"], now) - min(group["first_seen"], now) <= self.window):
                group["count"] += 1
                group["first_seen"] = min(group["first_seen"], now)
                group["last_seen"] = max(group["last_seen"], now)
                return "aggregated", group
            self.groups[key] = alert
        alert["alert_id"] = f"A{self._next_id:06d}"
        self._next_id += 1
        return "alert", alert

    def _expire(self, now):
        """Bỏ nhóm đã hết cửa sổ khỏi bộ nhớ; quét tối đa 1 lần/giây."""
        if self._next_sweep is not None and now < self._next_sweep:
            return
        self._next_sweep = now + 1
        for key in [k for k, g in self.groups.items() if now - g["first_seen"] > self.window]:
            del self.groups[key]

    def filter_reason(self, alert):
        """Lý do bỏ alert, hoặc None nếu giữ."""
        if SEVERITY_RANK[alert["severity"]] > self.min_rank:
            return f"severity {alert['severity']} dưới ngưỡng"
        for entry in self.suppress:
            if self._suppressed(entry, alert):
                shown = {k: v if isinstance(v, (int, str)) else str(v) for k, v in entry.items()}
                return f"suppress {shown}"
        return None

    @staticmethod
    def _suppressed(entry, alert):
        for field, expected in entry.items():
            value = alert[field]
            if field in ("src_ip", "dst_ip"):
                if ipaddress.ip_address(value) not in expected:
                    return False
            elif value != expected:
                return False
        return True

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
        """Detection Event → (alert chưa có alert_id, None), hoặc (None, lý do)
        nếu bị từ chối."""
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
            "first_seen": timestamp,
            "last_seen": timestamp,
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
        return alert, None
