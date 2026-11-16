# T15 — Swapped ports (regression cho flow key)

Testcase bổ sung sau khi sửa lỗi khóa flow: trước đây `_key()` sắp xếp IP và
port **riêng rẽ**, nên `A:1000 → B:2000` và `A:2000 → B:1000` cho ra cùng khóa
`(A, B, 1000, 2000)` và bị gộp nhầm thành 1 flow. Bản sửa sắp xếp theo cặp
`(ip, port)` nên mỗi endpoint giữ đúng port của nó.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T15_Swapped_Ports/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-02/T15_Swapped_Ports/input.pcap \
    -n 20 \
    -l TEST/Bai-tap-02/T15_Swapped_Ports
```

## Input

- `input.pcap` — 4 frame UDP giữa `10.0.0.1` và `10.0.0.2`:
  1. `10.0.0.1:1000 → 10.0.0.2:2000` (flow A, request)
  2. `10.0.0.1:2000 → 10.0.0.2:1000` (flow B, request — cùng IP, port đổi chỗ)
  3. `10.0.0.2:2000 → 10.0.0.1:1000` (flow A, response)
  4. `10.0.0.2:1000 → 10.0.0.1:2000` (flow B, response)

## Output

- `events.jsonl` (4 event) + `flows.jsonl` (2 flow).

## Kết quả

| Frame | 5-tuple | flow_id | direction |
|---|---|---|---|
| 1 | `10.0.0.1:1000 → 10.0.0.2:2000` | `flow-0001` | forward |
| 2 | `10.0.0.1:2000 → 10.0.0.2:1000` | `flow-0002` | forward |
| 3 | `10.0.0.2:2000 → 10.0.0.1:1000` | `flow-0001` | backward |
| 4 | `10.0.0.2:1000 → 10.0.0.1:2000` | `flow-0002` | backward |

2 flow tách biệt, mỗi flow `packet_count=2` (1 forward + 1 backward).
Với code cũ cả 4 frame đều rơi vào `flow-0001`.
