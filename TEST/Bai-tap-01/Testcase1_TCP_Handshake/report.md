# Testcase 1 — TCP handshake

Kiểm tra parser nhận diện đúng SYN, SYN/ACK, ACK.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-01/Testcase1_TCP_Handshake/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-01/Testcase1_TCP_Handshake/input.pcap \
    -n 10 \
    -l TEST/Bai-tap-01/Testcase1_TCP_Handshake
```

## Input

- `input.pcap` — 3 frame TCP không payload giữa client `192.168.1.10:51000`
  và server `192.168.1.20:80`, timestamp cố định `1700000000+i`.

## Output

- `events.jsonl` — 3 event, quan tâm `transport.flags`, `seq`, `ack`, `payload_length`.

## Kết quả

| Frame | Chiều | `transport.flags` | seq / ack | Nhận diện |
|---|---|---|---|---|
| 1 | client → server | `S` | 1000 / 0 | SYN |
| 2 | server → client | `SA` | 5000 / 1001 | SYN/ACK |
| 3 | client → server | `A` | 1001 / 5001 | ACK |

Cả 3 frame có `payload_length = 0`, `application.protocol = HTTP`, `type = UNKNOWN`
(nhận theo port 80, chưa có payload). Flow Tracker gán cả 3
frame vào cùng `flow-0001`, state `HANDSHAKE → HANDSHAKE → ESTABLISHED`.
