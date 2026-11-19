# TC11 — Severity statistics

Mục tiêu: báo cáo tính đúng tổng số alert, tổng count sau aggregation và phân bố severity
so với dữ liệu mẫu.

Trong báo cáo, `alerts` là số alert sau aggregation; `events` là tổng `count`, tức số
Detection Event thật đã gộp vào các alert đó.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC11_Severity_Statistics/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC11_Severity_Statistics/config.json \
    -D TEST/Bai-tap-04/TC11_Severity_Statistics/input.jsonl \
    -l TEST/Bai-tap-04/TC11_Severity_Statistics \
    -v \
    2> TEST/Bai-tap-04/TC11_Severity_Statistics/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC11_Severity_Statistics/config.json \
    -l TEST/Bai-tap-04/TC11_Severity_Statistics \
    --from 2025-11-15 --to 2025-11-15 \
    -o TEST/Bai-tap-04/TC11_Severity_Statistics/report_day.json \
    > TEST/Bai-tap-04/TC11_Severity_Statistics/report_day.txt
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC11_Severity_Statistics/config.json \
    -l TEST/Bai-tap-04/TC11_Severity_Statistics \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 \
    -o TEST/Bai-tap-04/TC11_Severity_Statistics/report_hour.json \
    > TEST/Bai-tap-04/TC11_Severity_Statistics/report_hour.txt
```

## Input

- `input.jsonl` (sinh bởi `gen_input.py`): 16 Detection Event ngày 2025-11-15, 5 SID với
  priority 1–4 (severity theo map mặc định).
- `config.json` — suppress SID 4110005; aggregation 60 giây.

Kết quả tính tay từ dữ liệu mẫu:

| Severity | Nhóm (alert) | Events |
|---|---|---|
| CRITICAL (4110001) | 10.0.0.5 ở giây 0/10/20 (3), 10.0.0.6 lúc 01:00:00/01:00:30 (2) | 2 alert, 5 events |
| HIGH (4110002) | 10.0.0.7 giây 100 (1), 10.0.0.7 giây 300 (1; cách 200 giây → nhóm mới), 10.0.0.8 lúc 01:01:40/01:01:50 (2) | 3 alert, 4 events |
| MEDIUM (4110003) | 10.0.0.9 giây 200 (1) | 1 alert, 1 event |
| LOW (4110004) | 10.0.0.5 giây 400/430 (2), 10.0.0.5 lúc 01:23:20 (1) | 2 alert, 3 events |
| 4110005 (suppress) | 3 event bị lọc | không đếm |

Mong đợi cả ngày: **8 alert, 13 events**. Riêng 01:00–01:59: CRITICAL 1/2, HIGH 1/2,
LOW 1/1, tức **3 alert, 5 events**.

## Output

- `engine.log` — `[alert] {'received': 16, 'alert': 8, 'aggregated': 5, 'filtered': 3}`.
- `report_day.txt` / `report_day.json` — báo cáo cả ngày.
- `report_hour.txt` / `report_hour.json` — báo cáo 01:00–01:59.
- `fast.log` — 8 alert.

## Kết quả

Cả ngày (`report_day.txt`):

```
Total alerts: 8 (events: 13) | Critical: 2 | High: 3 | Medium: 1 | Low: 2

Severity
  CRITICAL    alerts=2     events=5
  HIGH        alerts=3     events=4
  MEDIUM      alerts=1     events=1
  LOW         alerts=2     events=3
```

01:00–01:59 (`report_hour.txt`):

```
Total alerts: 3 (events: 5) | Critical: 1 | High: 1 | Medium: 0 | Low: 1
```

- Tổng và phân bố khớp đúng bảng tính tay ở cả hai khoảng thời gian.
- 3 event của SID bị suppress không xuất hiện trong số liệu: 16 event nhận vào = 13 events
  trong báo cáo + 3 bị lọc.
- `report_*.json` chứa cùng số liệu (`summary.total_alerts`, `summary.total_events`,
  `summary.severity`), vì text và JSON dựng từ cùng một dict.

**Đạt.**
