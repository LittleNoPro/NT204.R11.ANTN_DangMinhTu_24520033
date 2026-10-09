# T07 — TCP handshake

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T07_TCP_Handshake/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T07_TCP_Handshake/input.pcap \
    --count 50 --output TEST/Bai-tap-02/T07_TCP_Handshake/output.jsonl \
    --flows TEST/Bai-tap-02/T07_TCP_Handshake/flows.jsonl
```

## Input

- `input.pcap` — 3 frame `10.0.0.1:40000 ↔ 10.0.0.2:80`: SYN → SYN/ACK → ACK.

## Output

- `output.jsonl` (3 event, trường `flow`) + `flows.jsonl` (1 flow).

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | SYN (seq=1000) | `flow-0001`, `direction=forward`, `state=HANDSHAKE` |
| 2 | SYN/ACK (seq=2000, ack=1001) | cùng `flow_id`, `direction=backward`, `state=HANDSHAKE` |
| 3 | ACK (seq=1001, ack=2001) | cùng `flow_id`, `state=ESTABLISHED` |
| — | flow record | 1 flow: `packet_count=3`, `syn_count=2`, `state=ESTABLISHED`, `end_reason=eof` (pcap kết thúc khi chưa đóng) |
