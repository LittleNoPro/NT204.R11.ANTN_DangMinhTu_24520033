# TC08 — Event ngoài cửa sổ

Mục tiêu: Detection Event cùng khóa nhưng nằm ngoài aggregation window phải tạo
alert/nhóm mới.

Quy tắc: event được gộp vào nhóm đang mở nếu sau khi thêm, khoảng
`first_seen → last_seen` của nhóm vẫn ≤ `window`. Thời gian tính theo timestamp
packet, không theo đồng hồ máy.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC08_Outside_Window/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC08_Outside_Window/config.json \
    -r TEST/Bai-tap-04/TC08_Outside_Window/input.pcap \
    -l TEST/Bai-tap-04/TC08_Outside_Window \
    -v \
    2> TEST/Bai-tap-04/TC08_Outside_Window/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC08_Outside_Window/config.json \
    -l TEST/Bai-tap-04/TC08_Outside_Window \
    -a > TEST/Bai-tap-04/TC08_Outside_Window/alerts.jsonl
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC08_Outside_Window/config.json \
    -l TEST/Bai-tap-04/TC08_Outside_Window \
    --bucket minute \
    -o TEST/Bai-tap-04/TC08_Outside_Window/report.json \
    > TEST/Bai-tap-04/TC08_Outside_Window/report.txt
```

## Input

- `input.pcap` — một phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80; client gửi 6 request
  chứa `../` ở các giây **3, 30, 63, 64, 100, 200** (tính từ epoch 1763164800 =
  2025-11-15T00:00:00Z).
- `test.rules` — sid 4080001 `flow:to_server,established; content:"../"`, priority 1.
- `config.json` — `"aggregation": {"enabled": true, "window": 60}`.

Mong đợi:

| Giây | Khoảng của nhóm nếu gộp | Quyết định |
|---|---|---|
| 3 | — | nhóm 1 mới |
| 30 | 3 → 30 = 27 | gộp nhóm 1 |
| 63 | 3 → 63 = **60** (đúng biên) | gộp nhóm 1 |
| 64 | 3 → 64 = 61 > 60 | **nhóm 2 mới** |
| 100 | 64 → 100 = 36 | gộp nhóm 2 |
| 200 | 64 → 200 = 136 > 60 | **nhóm 3 mới** |

## Output

- `detections.jsonl` — 6 Detection Event.
- `alerts.jsonl` — Alert Object sau aggregation, đọc lại từ `alerts.db`.
- `report.txt`, `report.json` — báo cáo, chia theo phút (`--bucket minute`).
- `engine.log`, `fast.log` — mỗi nhóm mới sinh một dòng alert.
- `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`[alert] {'received': 6, 'alert': 3, 'aggregated': 3}`

| alert_id | count | first_seen | last_seen |
|---|---|---|---|
| A000001 | 3 | 1763164803.0 (giây 3) | 1763164863.0 (giây 63) |
| A000002 | 2 | 1763164864.0 (giây 64) | 1763164900.0 (giây 100) |
| A000003 | 1 | 1763165000.0 (giây 200) | 1763165000.0 (giây 200) |

- Event ở giây 63 nằm đúng biên (60 giây) nên vẫn được gộp; giây 64 vượt 1 giây nên mở
  nhóm mới.
- Báo cáo theo phút khớp với các nhóm:
  `00:00 → 1 alert / 3 events`, `00:01 → 1 / 2`, `00:03 → 1 / 1`.

**Đạt.**
