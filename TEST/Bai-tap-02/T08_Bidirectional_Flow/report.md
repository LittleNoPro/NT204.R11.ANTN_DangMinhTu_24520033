# T08 — Bidirectional flow

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T08_Bidirectional_Flow/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-02/T08_Bidirectional_Flow/input.pcap \
    -n 50 \
    -l TEST/Bai-tap-02/T08_Bidirectional_Flow
```

## Input

- `input.pcap` — 3 frame cùng 5-tuple `10.0.0.1:40000 ↔ 10.0.0.2:80`:
  request A→B, response B→B→A, ACK A→B.

## Output

- `events.jsonl` (3 event) + `flows.jsonl` (1 flow).

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | HTTP request A→B | `direction=forward` |
| 2 | HTTP response B→A (đảo chiều) | **cùng `flow_id`**, `direction=backward` |
| 3 | ACK A→B | cùng `flow_id`, `direction=forward` |
| — | flow record | 1 flow duy nhất: `forward.packet_count=2`, `backward.packet_count=1`, `packet_count=3` |
