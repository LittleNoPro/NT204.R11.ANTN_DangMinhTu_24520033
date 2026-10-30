# T14 — Detection Event

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T14_Detection_Event/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T14_Detection_Event/input.pcap \
    --count 50 --output TEST/BT3/T14_Detection_Event/output.jsonl \
    --rules TEST/BT3/T14_Detection_Event/test.rules \
    --rules-report TEST/BT3/T14_Detection_Event/rules_report.jsonl \
    --alerts TEST/BT3/T14_Detection_Event/alerts.jsonl --trace TEST/BT3/T14_Detection_Event/trace.jsonl \
    2> TEST/BT3/T14_Detection_Event/engine.log
```

## Input

- `input.pcap` — phiên 10.0.0.5:52133 → 192.168.1.20:80 (ví dụ trong đề): handshake rồi
  `GET /static/../../etc/passwd`.
- `test.rules` — sid 100001 rev 1 `Directory traversal detected`, priority 1,
  `flow:to_server,established; content:"../"`.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

1 Detection Event cho frame 4 (`alerts.jsonl`):

| Field | Giá trị |
|---|---|
| `timestamp` / `packet_id` | 1700000003.0 / 4 |
| `sid` / `rev` | 100001 / 1 |
| `msg` / `priority` / `classtype` | Directory traversal detected / 1 / web-application-attack |
| 5-tuple + protocol | 10.0.0.5:52133 → 192.168.1.20:80 / TCP |
| `application_protocol` / `flow_id` | HTTP / flow-0001 |
| `flow_direction` / `flow_state` | forward / ESTABLISHED |
| `match` | `contents=[{"content": "../", "buffer": "payload", "offset": 12}]`, `flow={to_server, established}` |

Frame 1 (SYN) bị loại `stage=flow`; frame 3 (ACK rỗng) bị loại `stage=content`.
