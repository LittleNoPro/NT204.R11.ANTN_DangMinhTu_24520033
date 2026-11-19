# TC02 — Priority → severity

Mục tiêu: priority của rule được ánh xạ đúng sang severity theo cấu hình
(`alert.severity_map`), không hard-code trong chương trình.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC02_Priority_Severity/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC02_Priority_Severity/config.json \
    -r TEST/Bai-tap-04/TC02_Priority_Severity/input.pcap \
    -l TEST/Bai-tap-04/TC02_Priority_Severity \
    -v \
    2> TEST/Bai-tap-04/TC02_Priority_Severity/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC02_Priority_Severity/config.json \
    -l TEST/Bai-tap-04/TC02_Priority_Severity \
    -a > TEST/Bai-tap-04/TC02_Priority_Severity/alerts.jsonl
```

## Input

- `input.pcap` — phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80, request
  `GET /admin/config.php` khớp cùng lúc 7 rule.
- `test.rules` — 7 rule khác SID, priority lần lượt 1, 2, 3, 4, 5, 7 và một rule không
  khai báo priority.
- `config.json` — severity map **khác mặc định**:
  ```json
  "severity_map": {"1": "CRITICAL", "2": "HIGH", "3": "HIGH", "4": "MEDIUM", "6": "LOW"}
  ```
  Mỗi khóa là đầu một khoảng: 4–5 → MEDIUM, từ 6 trở lên → LOW. Rule không có priority
  nhận mức của khóa lớn nhất (LOW).

## Output

- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db` (`report.py -a`).
- `fast.log`, `engine.log` — alert dạng ngắn và thống kê.
- `detections.jsonl`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

| alert_id | sid | priority | Mong đợi | severity thực tế |
|---|---|---|---|---|
| A000001 | 4020001 | 1 | CRITICAL | CRITICAL |
| A000002 | 4020002 | 2 | HIGH | HIGH |
| A000003 | 4020003 | 3 | HIGH (map riêng, mặc định là MEDIUM) | HIGH |
| A000004 | 4020004 | 4 | MEDIUM | MEDIUM |
| A000005 | 4020005 | 5 | MEDIUM (khoảng 4–5) | MEDIUM |
| A000006 | 4020007 | 7 | LOW (khoảng 6+) | LOW |
| A000007 | 4020009 | — | LOW (không có priority) | LOW |

Severity sai trong config (ví dụ `"1": "URGENT"`) bị từ chối lúc khởi động:
`[config] ...: alert.severity_map: 'URGENT' không thuộc ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']`.

**Đạt.**
