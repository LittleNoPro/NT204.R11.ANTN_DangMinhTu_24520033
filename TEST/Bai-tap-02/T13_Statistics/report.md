# T13 — Statistics

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T13_Statistics/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T13_Statistics/input.pcap \
    --count 50 --output TEST/Bai-tap-02/T13_Statistics/output.jsonl \
    --flows TEST/Bai-tap-02/T13_Statistics/flows.jsonl
```

## Input

- `input.pcap` — 10 frame TCP `10.0.0.1:40000 ↔ 10.0.0.2:80`, 2s mỗi frame
  (duration=18s), xen kẽ 2 chiều:
  handshake (S, SA, A) → 2×data A→B (payload 100B) + 2×data B→A (payload 50B)
  → FIN/ACK cả hai chiều → ACK cuối.

## Output

- `flows.jsonl` — 1 flow record đầy đủ §5.4.

## Kết quả

| Nhóm | Field | Giá trị (tính trước từ pcap) |
|---|---|---|
| Định danh | `flow_id` / `protocol` | `flow-0001` / `TCP` |
| Thời gian | `duration` = last_seen − start_time | **18.0s** (9 khoảng × 2s) |
| Tổng thể | `packet_count` / `byte_count` | **10** / tổng `ip_length` 10 packet (fwd+bwd = byte_count) |
| Hai chiều | forward | `packet_count=6` (S, A, 2×data, FA, A cuối) |
| Hai chiều | backward | `packet_count=4` (SA, 2×data, FA) |
| TCP | `syn_count` | **2** (S + SA) |
| TCP | `ack_count` | **9** (mọi packet có cờ A) |
| TCP | `fin_count` / `rst_count` | **2** / **0** |
| TCP | `state` / `end_reason` | `CLOSED` / `closed` |
