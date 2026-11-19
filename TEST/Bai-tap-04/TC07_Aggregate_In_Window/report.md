# TC07 — Event lặp trong cửa sổ

Mục tiêu: Detection Event lặp lại cùng khóa `(sid, src_ip, dst_ip)` trong aggregation
window được gom vào một alert; `count`, `first_seen`, `last_seen` chính xác.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC07_Aggregate_In_Window/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC07_Aggregate_In_Window/config.json \
    -r TEST/Bai-tap-04/TC07_Aggregate_In_Window/input.pcap \
    -l TEST/Bai-tap-04/TC07_Aggregate_In_Window \
    -v \
    2> TEST/Bai-tap-04/TC07_Aggregate_In_Window/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC07_Aggregate_In_Window/config.json \
    -l TEST/Bai-tap-04/TC07_Aggregate_In_Window \
    -a > TEST/Bai-tap-04/TC07_Aggregate_In_Window/alerts.jsonl
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC07_Aggregate_In_Window/config.json \
    -l TEST/Bai-tap-04/TC07_Aggregate_In_Window \
    -o TEST/Bai-tap-04/TC07_Aggregate_In_Window/report.json \
    > TEST/Bai-tap-04/TC07_Aggregate_In_Window/report.txt
```

## Input

- `input.pcap` — một phiên HTTP 10.0.0.5:52133 → 192.168.1.20:80; sau handshake client
  gửi 5 request chứa `../` ở các giây **3, 13, 23, 33, 45** (tính từ 2025-11-15T00:00:00Z,
  epoch 1763164800).
- `test.rules` — sid 4070001 `flow:to_server,established; content:"../"`, priority 1.
- `config.json` — `"aggregation": {"enabled": true, "window": 60}`.

Khoảng từ event đầu tới event cuối là 45 − 3 = 42 giây ≤ 60, nên cả 5 event thuộc một nhóm.

## Output

- `detections.jsonl` — 5 Detection Event (Core Engine không gom nhóm).
- `alerts.jsonl` — Alert Object sau aggregation, đọc lại từ `alerts.db`.
- `report.txt`, `report.json` — báo cáo trên dữ liệu đã lưu.
- `engine.log`, `fast.log` — chỉ alert mới được in, event gộp thêm không sinh dòng mới.
- `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`[alert] {'received': 5, 'alert': 1, 'aggregated': 4}`: 5 Detection Event thành 1 alert.

| Trường | Mong đợi | Thực tế |
|---|---|---|
| `alert_id` | 1 alert duy nhất | A000001 |
| `count` | 5 | 5 |
| `first_seen` | 1763164803.0 (giây 3) | 1763164803.0 |
| `last_seen` | 1763164845.0 (giây 45) | 1763164845.0 |
| `packet_id`, `src_port`, `flow_id` | của event đầu tiên | 4, 52133, flow-0001 |

Event gộp thêm cập nhật chính dòng A000001 trong `alerts.db` (theo `alert_id`) chứ không
tạo dòng mới. Báo cáo phân biệt alert và event: `Total alerts: 1 (events: 5)`.

**Đạt.**
