# TC01 — Detection Event hợp lệ

Mục tiêu: Detection Event hợp lệ tạo Alert Object có đủ trường bắt buộc và `alert_id` duy nhất.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC01_Valid_Detection_Event/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC01_Valid_Detection_Event/config.json \
    -r TEST/Bai-tap-04/TC01_Valid_Detection_Event/input.pcap \
    -l TEST/Bai-tap-04/TC01_Valid_Detection_Event \
    -v \
    2> TEST/Bai-tap-04/TC01_Valid_Detection_Event/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC01_Valid_Detection_Event/config.json \
    -l TEST/Bai-tap-04/TC01_Valid_Detection_Event \
    -a > TEST/Bai-tap-04/TC01_Valid_Detection_Event/alerts.jsonl
```

## Input

- `input.pcap` — 3 tấn công khác SID, khác cặp IP (để không bị gom nhóm):
  1. 10.0.0.5:52133 → 192.168.1.20:80: handshake rồi `GET /static/../../etc/passwd`
  2. 10.0.0.6:40001 → 192.168.1.21:80: handshake rồi `GET /login?user='%20OR%201=1--`
  3. 10.0.0.7:5353 → 192.168.1.53:53: DNS query `malware.example`
- `test.rules` — sid 4010001 (priority 1), 4010002 (priority 2, rev 2), 4010003 (priority 3).
- `config.json` — cấu hình alert mặc định: severity map 1→CRITICAL … 4→LOW, không lọc,
  aggregation 60 giây, lưu SQLite trong thư mục log.

## Output

- `detections.jsonl` — Detection Event do Core Engine sinh (đầu vào của Alert Module).
- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db` bằng `report.py -a`.
- `fast.log` — alert dạng ngắn (cũng in ra console trong `engine.log` vì có `-v`).
- `engine.log` — thống kê engine và Alert Manager.
- `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl` — log của pipeline.

## Kết quả

`engine.log`: `[alert] {'received': 3, 'alert': 3}`: 3 Detection Event đều hợp lệ, tạo 3 alert.

| alert_id | sid:rev | severity (priority) | protocol / app | src → dst | flow_id | packet_id |
|---|---|---|---|---|---|---|
| A000001 | 4010001:1 | CRITICAL (1) | TCP / HTTP | 10.0.0.5:52133 → 192.168.1.20:80 | flow-0001 | 4 |
| A000002 | 4010002:2 | HIGH (2) | TCP / HTTP | 10.0.0.6:40001 → 192.168.1.21:80 | flow-0002 | 8 |
| A000003 | 4010003:1 | MEDIUM (3) | UDP / DNS | 10.0.0.7:5353 → 192.168.1.53:53 | flow-0003 | 9 |

- `alert_id` duy nhất, tăng dần A000001 → A000003.
- Đủ trường bắt buộc: `alert_id`, `sid`, `rev`, `msg`, `severity`, `priority`, `classtype`,
  `protocol`, `application_protocol`, `src_ip`/`src_port`, `dst_ip`/`dst_port`, `flow_id`,
  `first_seen`/`last_seen` (epoch, đã chuẩn hóa từ timestamp), `count = 1`, `status = "ok"`.
- Alert 2 khớp nhờ Decoder: `' OR 1=1` nằm trong `uri_decoded` của path đã percent-decode.

**Đạt.**
