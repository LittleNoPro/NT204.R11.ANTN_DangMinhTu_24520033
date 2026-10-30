# T08 — flow:to_server,established

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T08_Flow_State/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T08_Flow_State/input.pcap \
    --count 50 --output TEST/BT3/T08_Flow_State/output.jsonl \
    --rules TEST/BT3/T08_Flow_State/test.rules \
    --rules-report TEST/BT3/T08_Flow_State/rules_report.jsonl \
    --alerts TEST/BT3/T08_Flow_State/alerts.jsonl --trace TEST/BT3/T08_Flow_State/trace.jsonl \
    2> TEST/BT3/T08_Flow_State/engine.log
```

## Input

- `input.pcap` — frame 1 SYN mang payload `GET /early`, frame 2 SYN/ACK, frame 3 ACK,
  frame 4 GET (client → server), frame 5 `HTTP/1.1 200 OK` (server → client).
- `test.rules` — 3080001 `to_server,established` + GET; 3080002 `to_client,established` + 200;
  3080003 `to_server,not_established` + GET; 3080004 `to_server` nhưng rule đặt ở chiều response.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

Flow context lấy từ Flow Tracker: `to_server` = packet chiều forward (phía khởi tạo),
`established` = TCP state `ESTABLISHED`/`CLOSING`.

| Frame | Flow state / chiều | Match | Bị loại |
|---|---|---|---|
| 1 SYN+`GET /early` | HANDSHAKE, to_server | **3080003** | 3080001 `stage=flow` (not established) |
| 2 SYN/ACK | HANDSHAKE, to_client | — | 3080002, 3080004 `stage=flow` |
| 3 ACK | ESTABLISHED, to_server | — | 3080001 `stage=content` (không payload), 3080003 `stage=flow` |
| 4 GET | ESTABLISHED, to_server | **3080001** | 3080003 `stage=flow` (đã established) |
| 5 200 OK | ESTABLISHED, to_client | **3080002** | 3080004 `stage=flow` (không phải to_server) |
