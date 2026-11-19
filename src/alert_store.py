"""Module Alert Repository.

Lưu Alert Object bền vững trong SQLite (thư viện chuẩn sqlite3) và cho phép
truy vấn theo khoảng thời gian, severity, SID, IP, protocol. Report Module chỉ
đọc từ đây, không cần packet gốc.

Bảng:
- alerts     một dòng mỗi alert; alert được gộp thêm event thì cập nhật
             count/first_seen/last_seen trên chính dòng đó (theo alert_id)
- discarded  Detection Event bị từ chối (rejected) hoặc bị lọc (filtered),
             kèm lý do — không lẫn với alert thông thường

Dữ liệu được giữ qua các lần chạy; alert_id tiếp nối số lớn nhất đã có.
"""

import json
import os
import sqlite3

ALERT_COLUMNS = (
    "alert_id", "sid", "rev", "msg", "severity", "priority", "classtype",
    "protocol", "application_protocol", "src_ip", "src_port", "dst_ip", "dst_port",
    "flow_id", "packet_id", "first_seen", "last_seen", "count", "status", "reason",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    sid INTEGER NOT NULL, rev INTEGER, msg TEXT,
    severity TEXT NOT NULL, priority INTEGER, classtype TEXT,
    protocol TEXT NOT NULL, application_protocol TEXT,
    src_ip TEXT NOT NULL, src_port INTEGER,
    dst_ip TEXT NOT NULL, dst_port INTEGER,
    flow_id TEXT, packet_id INTEGER,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, count INTEGER NOT NULL,
    status TEXT, reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(first_seen, last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts(sid);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst ON alerts(dst_ip);
CREATE TABLE IF NOT EXISTS discarded (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,      -- rejected | filtered
    reason TEXT,
    event TEXT                 -- JSON của Detection Event / alert bị bỏ
);
"""


class AlertStore:
    def __init__(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.commit()
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def next_id(self):
        """Số thứ tự cho alert_id kế tiếp (A000001 → 1), tiếp nối lần chạy trước."""
        row = self.db.execute(
            "SELECT MAX(CAST(SUBSTR(alert_id, 2) AS INTEGER)) FROM alerts").fetchone()
        return (row[0] or 0) + 1

    def save(self, alert):
        """Thêm alert mới hoặc cập nhật alert đã gộp (cùng alert_id)."""
        placeholders = ", ".join("?" for _ in ALERT_COLUMNS)
        updates = ", ".join(f"{c} = excluded.{c}" for c in ("first_seen", "last_seen", "count"))
        self.db.execute(
            f"INSERT INTO alerts ({', '.join(ALERT_COLUMNS)}) VALUES ({placeholders}) "
            f"ON CONFLICT(alert_id) DO UPDATE SET {updates}",
            [alert.get(c) for c in ALERT_COLUMNS])
        self.db.commit()          # commit mỗi alert: tiến trình dừng đột ngột không mất alert

    def discard(self, status, reason, event):
        self.db.execute("INSERT INTO discarded (status, reason, event) VALUES (?, ?, ?)",
                        (status, reason, json.dumps(event, default=str, ensure_ascii=False)))
        self.db.commit()

    def query(self, start=None, end=None, severity=None, sid=None,
              src_ip=None, dst_ip=None, protocol=None):
        """Alert có khoảng first_seen..last_seen giao với [start, end], lọc thêm
        theo các tiêu chí còn lại (None = không lọc). severity và sid nhận một
        giá trị hoặc danh sách. Trả về list dict, sắp theo first_seen."""
        where, params = [], []
        if start is not None:
            where.append("last_seen >= ?")
            params.append(start)
        if end is not None:
            where.append("first_seen <= ?")
            params.append(end)
        for column, value in (("severity", severity), ("sid", sid), ("src_ip", src_ip),
                              ("dst_ip", dst_ip), ("protocol", protocol)):
            if value is None:
                continue
            values = list(value) if isinstance(value, (list, tuple, set)) else [value]
            where.append(f"{column} IN ({', '.join('?' for _ in values)})")
            params.extend(values)
        sql = "SELECT * FROM alerts"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY first_seen, alert_id"
        return [dict(row) for row in self.db.execute(sql, params)]

    def discarded(self, status=None):
        sql, params = "SELECT status, reason, event FROM discarded", []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        return [{"status": s, "reason": r, "event": json.loads(e)}
                for s, r, e in self.db.execute(sql + " ORDER BY id", params)]
