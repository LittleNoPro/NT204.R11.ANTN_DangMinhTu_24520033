# T11 — Concurrent flows

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T11_Concurrent_Flows/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T11_Concurrent_Flows/input.pcap \
    --count 50 --output TEST/Bai-tap-02/T11_Concurrent_Flows/output.jsonl \
    --flows TEST/Bai-tap-02/T11_Concurrent_Flows/flows.jsonl
```

## Input

- `input.pcap` — 6 frame, 3 flow xen kẽ (request+response mỗi flow):
  - `10.0.0.1:40000 → 10.0.0.2:80`
  - `10.0.0.1:40001 → 10.0.0.2:80` (khác source port, cùng dest — 2 flow phải tách)
  - `10.0.0.3:50000 → 10.0.0.2:443` (khác host + port)

## Output

- `output.jsonl` (6 event) + `flows.jsonl` (3 flow).

## Kết quả

| Flow | Nội dung | Kết quả |
|---|---|---|
| 1 | `40000↔80` | `flow_id` riêng, `packet_count=2` (request+response) |
| 2 | `40000↔80` vs `40001↔80` | **không gộp nhầm** — 2 flow_id khác nhau dù cùng dst host+port |
| 3 | `50000↔443` host khác | `flow_id` riêng, `packet_count=2` |
| — | tổng | 3 flow, 3 `flow_id` duy nhất — không flow nào bị trộn |
