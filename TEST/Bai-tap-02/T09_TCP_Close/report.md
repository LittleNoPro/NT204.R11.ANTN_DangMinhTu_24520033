# T09 — TCP close (FIN / RST)

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T09_TCP_Close/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T09_TCP_Close/input.pcap \
    --count 50 --output TEST/Bai-tap-02/T09_TCP_Close/output.jsonl \
    --flows TEST/Bai-tap-02/T09_TCP_Close/flows.jsonl
```

## Input

- `input.pcap` — 9 frame, 2 flow:
  - flow 1 (port 40000→80): handshake + FIN/ACK cả hai chiều + ACK cuối
  - flow 2 (port 41000→443): handshake + RST

## Output

- `output.jsonl` (9 event) + `flows.jsonl` (2 flow).

## Kết quả

| Frame / Flow | Nội dung | Kết quả |
|---|---|---|
| flow1 frame 4 | FIN/ACK từ A | `state=CLOSING`, `fin_count=1` |
| flow1 frame 5 | FIN/ACK từ B | `state=CLOSED`, `fin_count=2` — flow record `end_reason=closed` |
| flow1 frame 6 | ACK cuối (theo RFC) | vẫn vào đúng flow cũ (không tạo flow lạc), `packet_count=6` |
| flow2 frame 9 | RST từ B | `state=RESET` ngay lập tức, flow record `end_reason=reset`, `rst_count=1` |
