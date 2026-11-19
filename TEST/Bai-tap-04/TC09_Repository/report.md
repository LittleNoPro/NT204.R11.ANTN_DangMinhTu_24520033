# TC09 — Repository

Mục tiêu: alert được lưu bền vững trong Alert Repository (SQLite) và đọc lại không mất
trường bắt buộc; dữ liệu đủ cho Report Module mà không cần đọc lại packet.

Testcase dùng `alert.storage.path` riêng (`repo.db`): đây là kho lâu dài, được giữ qua
các lần chạy (khác với mặc định `<thư mục log>/alerts.db` được tạo mới mỗi lần chạy).

## Cách chạy

```bash
rm -f TEST/Bai-tap-04/TC09_Repository/repo.db
.venv/bin/python TEST/Bai-tap-04/TC09_Repository/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC09_Repository/config.json \
    -r TEST/Bai-tap-04/TC09_Repository/input.pcap \
    -l TEST/Bai-tap-04/TC09_Repository \
    -v \
    2> TEST/Bai-tap-04/TC09_Repository/engine_run1.log
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC09_Repository/config.json \
    -r TEST/Bai-tap-04/TC09_Repository/input.pcap \
    -l TEST/Bai-tap-04/TC09_Repository \
    -v \
    2> TEST/Bai-tap-04/TC09_Repository/engine_run2.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC09_Repository/config.json \
    -a > TEST/Bai-tap-04/TC09_Repository/alerts.jsonl
.venv/bin/python TEST/Bai-tap-04/TC09_Repository/verify.py \
    > TEST/Bai-tap-04/TC09_Repository/verify.txt
```

## Input

- `input.pcap` — 3 tấn công:
  1. 10.0.0.5:52133 → 192.168.1.20:80 HTTP `GET /static/../../etc/passwd` (TCP)
  2. 10.0.0.7:5353 → 192.168.1.53:53 DNS query `malware.example` (UDP)
  3. 10.0.0.6:40001 → 192.168.1.21:80 HTTP `GET /login?user='%20OR%201=1--` (TCP)
- `test.rules` — 4090001 (priority 1, rev 3), 4090002 (priority 2), 4090003 **không có
  priority/classtype** để kiểm tra giá trị `null` cũng được lưu và đọc lại đúng.
- `config.json` — `"storage": {"type": "sqlite", "path": "TEST/Bai-tap-04/TC09_Repository/repo.db"}`
  (đường dẫn tính từ thư mục chạy lệnh).

IDS chạy **hai lần** trên cùng pcap, ghi vào cùng `repo.db`.

## Output

- `engine_run1.log`, `engine_run2.log` — alert và thống kê của từng lần chạy.
- `alerts.jsonl` — toàn bộ alert đọc lại từ `repo.db` (`report.py -a`).
- `verify.py` / `verify.txt` — so từng alert đọc lại với Detection Event gốc
  (`detections.jsonl`, ghép theo `sid` + `packet_id`): đủ 20 cột của bảng `alerts`, trường
  bắt buộc khác null, giá trị khớp (`first_seen` = `timestamp` của event), `alert_id`
  không trùng.
- `repo.db` không commit (`*.db` trong `.gitignore`); chạy lại các lệnh trên để tạo.
- `detections.jsonl`, `fast.log`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`,
  `rules_report.jsonl` — của lần chạy thứ hai.

## Kết quả

| Lần chạy | Alert mới | alert_id |
|---|---|---|
| 1 | 3 | A000001–A000003 |
| 2 | 3 | **A000004–A000006** (nối tiếp, không ghi đè) |

`verify.txt`:

```
A000001  sid=4090001  20 trường  OK
A000004  sid=4090001  20 trường  OK
A000002  sid=4090002  20 trường  OK
A000005  sid=4090002  20 trường  OK
A000003  sid=4090003  20 trường  OK
A000006  sid=4090003  20 trường  OK
6 alert, 20 cột mỗi alert, alert_id duy nhất: PASS
```

- Alert của lần chạy 1 vẫn còn sau khi chương trình kết thúc và chạy lại: lưu bền vững.
- `alert_id` lần 2 tiếp nối từ số lớn nhất trong kho, nên không trùng.
- Alert từ rule 4090003 lưu `priority = null`, `classtype = null`, severity LOW, đọc lại
  đúng như vậy.
- Lần chạy 2 tạo alert mới thay vì gộp vào alert cũ: nhóm aggregation chỉ tồn tại trong
  một lần chạy, không được khôi phục từ kho.

**Đạt.**

## Ghi chú

Rule protocol `icmp` hiện bị Rule Parser đánh dấu `unsupported`, và rule `ip` chưa so
`content` trên payload ICMP. Vì vậy testcase dùng TCP/UDP.
