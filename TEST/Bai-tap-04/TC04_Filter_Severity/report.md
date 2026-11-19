# TC04 — Filter theo severity

Mục tiêu: alert có severity dưới ngưỡng cấu hình (`alert.min_severity`) bị loại đúng,
không được lưu thành alert.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC04_Filter_Severity/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC04_Filter_Severity/config.json \
    -r TEST/Bai-tap-04/TC04_Filter_Severity/input.pcap \
    -l TEST/Bai-tap-04/TC04_Filter_Severity \
    -v \
    2> TEST/Bai-tap-04/TC04_Filter_Severity/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC04_Filter_Severity/config.json \
    -l TEST/Bai-tap-04/TC04_Filter_Severity \
    -a > TEST/Bai-tap-04/TC04_Filter_Severity/alerts.jsonl
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC04_Filter_Severity/config.json \
    -l TEST/Bai-tap-04/TC04_Filter_Severity \
    -o TEST/Bai-tap-04/TC04_Filter_Severity/report.json \
    > TEST/Bai-tap-04/TC04_Filter_Severity/report.txt
```

## Input

- `input.pcap` — phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80, request
  `GET /admin/config.php` khớp cùng lúc 4 rule.
- `test.rules` — 4 rule priority 1–4, tương ứng CRITICAL, HIGH, MEDIUM, LOW theo severity
  map mặc định.
- `config.json` — `"alert": {"min_severity": "HIGH"}`: chỉ giữ alert từ HIGH trở lên.

## Output

- `engine.log` — alert được giữ và dòng `[alert] filtered: ...` cho alert bị loại (do `-v`).
- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db`.
- `report.txt`, `report.json` — báo cáo trên dữ liệu đã lưu.
- `detections.jsonl` — 4 Detection Event do Core Engine sinh (trước khi lọc).
- `fast.log`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`[alert] {'received': 4, 'alert': 2, 'filtered': 2}`

| sid | severity | Mong đợi | Thực tế |
|---|---|---|---|
| 4040001 | CRITICAL | giữ | A000001 |
| 4040002 | HIGH | giữ (bằng ngưỡng) | A000002 |
| 4040003 | MEDIUM | loại | `filtered: sid 4040003: severity MEDIUM dưới ngưỡng HIGH` |
| 4040004 | LOW | loại | `filtered: sid 4040004: severity LOW dưới ngưỡng HIGH` |

- `detections.jsonl` vẫn có đủ 4 Detection Event: Core Engine không biết về bộ lọc, việc
  lọc chỉ nằm ở Alert Module.
- Alert bị loại không chiếm `alert_id` và không có trong `alerts.jsonl`. Chúng nằm ở bảng
  `discarded` (status `filtered`) của `alerts.db`.
- Báo cáo khớp dữ liệu đã lưu:
  `Total alerts: 2 (events: 2) | Critical: 1 | High: 1 | Medium: 0 | Low: 0`.

**Đạt.**
