# T17 — Chính sách skip theo cấu hình

Testcase bổ sung cho yêu cầu chung của BT2: "giới hạn kích thước hoặc chính
sách bỏ qua packet phải cấu hình được" và mục Missing/unsupported data
"đánh dấu hoặc bỏ qua theo cấu hình".

| Tùy chọn | Mặc định | Tác dụng |
|---|---|---|
| `--skip-unknown` | tắt | event có application protocol `UNKNOWN` → `processing_action = skip` (mặc định chỉ đánh dấu `partial` + `continue`) |
| `--max-payload N` | không giới hạn | payload lớn hơn N byte → `partial` + `skip`, `reason` ghi kích thước |

Event bị `skip` vẫn được ghi ra `output.jsonl` và vẫn được Flow Tracker đếm
vào thống kê flow, nhưng Core Engine (BT3) không đánh giá rule trên event đó.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T17_Skip_Policy/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T17_Skip_Policy/input.pcap \
    --count 20 --output TEST/Bai-tap-02/T17_Skip_Policy/output.jsonl \
    --skip-unknown --max-payload 200 \
    --rules-config rules/engine.json --alerts TEST/Bai-tap-02/T17_Skip_Policy/alerts.jsonl \
    2> TEST/Bai-tap-02/T17_Skip_Policy/engine.log
```

## Input

- `input.pcap` — 3 frame:
  1. HTTP GET `/../etc` (payload 43 byte)
  2. HTTP GET `/../AAAA…` (payload 340 byte) — cũng chứa `../`
  3. UDP `10.0.0.3:5000 → 10.0.0.4:9999`, payload `hello` (application UNKNOWN)

## Output

- `output.jsonl` (3 event), `alerts.jsonl` (Detection Event), `engine.log` (thống kê engine).

## Kết quả

| Frame | preprocess_status | processing_action | reason | Engine |
|---|---|---|---|---|
| 1 | `valid` | `continue` | — | đánh giá, **match sid 1000001** |
| 2 | `partial` | `skip` | `payload 340 bytes exceeds max_payload 200` | bỏ qua (không alert dù có `../`) |
| 3 | `partial` | `skip` | `application protocol unknown` | bỏ qua |

`engine.log`: `events_evaluated: 1`, `events_skipped: 2`, `matches: 1`.
Chạy lại không có hai tùy chọn trên thì frame 2 và 3 là `continue`
(hành vi mặc định như các testcase T01–T16).
