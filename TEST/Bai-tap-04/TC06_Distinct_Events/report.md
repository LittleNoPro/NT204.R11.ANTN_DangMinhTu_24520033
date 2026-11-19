# TC06 — Hai event khác nhau

Mục tiêu: Detection Event khác khóa gom nhóm `(sid, src_ip, dst_ip)` tạo alert/nhóm độc
lập, kể cả khi xảy ra trong cùng một aggregation window.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC06_Distinct_Events/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC06_Distinct_Events/config.json \
    -r TEST/Bai-tap-04/TC06_Distinct_Events/input.pcap \
    -l TEST/Bai-tap-04/TC06_Distinct_Events \
    -v \
    2> TEST/Bai-tap-04/TC06_Distinct_Events/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC06_Distinct_Events/config.json \
    -l TEST/Bai-tap-04/TC06_Distinct_Events \
    -a > TEST/Bai-tap-04/TC06_Distinct_Events/alerts.jsonl
```

## Input

- `input.pcap` — 3 phiên HTTP trong vòng 12 giây:
  1. 10.0.0.5 → 192.168.1.20 `GET /../etc/passwd`: khớp cả 2 rule
  2. 10.0.0.6 → 192.168.1.20 `GET /../index.html`
  3. 10.0.0.5 → 192.168.1.21 `GET /../index.html`
- `test.rules` — 4060001 `content:"../"` (priority 2), 4060002 `content:"passwd"` (priority 1).
- `config.json` — aggregation bật, window 60 giây: mọi event đều nằm trong cùng một cửa
  sổ, nên nếu bị tách thì lý do chỉ có thể là khóa khác nhau.

## Output

- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db`.
- `engine.log`, `fast.log` — alert dạng ngắn và thống kê.
- `detections.jsonl`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`[alert] {'received': 4, 'alert': 4}`: 4 Detection Event, 4 alert, không event nào bị gộp.

| alert_id | sid | src_ip | dst_ip | count | Khác A000001 ở |
|---|---|---|---|---|---|
| A000001 | 4060001 | 10.0.0.5 | 192.168.1.20 | 1 | (gốc) |
| A000002 | 4060002 | 10.0.0.5 | 192.168.1.20 | 1 | `sid` |
| A000003 | 4060001 | 10.0.0.6 | 192.168.1.20 | 1 | `src_ip` |
| A000004 | 4060001 | 10.0.0.5 | 192.168.1.21 | 1 | `dst_ip` |

Mỗi alert có `count = 1` và `first_seen = last_seen` riêng: các nhóm độc lập với nhau.

**Đạt.**
