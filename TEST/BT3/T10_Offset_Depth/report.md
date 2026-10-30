# T10 — offset/depth

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T10_Offset_Depth/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T10_Offset_Depth/input.pcap \
    --count 50 --output TEST/BT3/T10_Offset_Depth/output.jsonl \
    --rules TEST/BT3/T10_Offset_Depth/test.rules \
    --rules-report TEST/BT3/T10_Offset_Depth/rules_report.jsonl \
    --alerts TEST/BT3/T10_Offset_Depth/alerts.jsonl --trace TEST/BT3/T10_Offset_Depth/trace.jsonl \
    2> TEST/BT3/T10_Offset_Depth/engine.log
```

## Input

- `test.rules` — 3100001 `GET` offset 0 depth 3; 3100002 `passwd` offset 4 depth 20
  (vùng byte 4–23); 3100003 `secret` offset 30.
- `input.pcap` — 5 payload đặt pattern trong/ngoài vùng.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Frame | Payload | Vị trí pattern | Match |
|---|---|---|---|
| 1 | `GET /etc/passwd ...` | GET@0, passwd@9 | 3100001, 3100002 |
| 2 | `POST /GET ...` | GET@6 (ngoài depth 3) | — |
| 3 | `GET /aaaa…a/passwd` | GET@0, passwd@27 (ngoài 4–23) | 3100001 |
| 4 | `secret token at ...` | secret@0 (trước offset 30) | — |
| 5 | `"x"*30 + "secret"` | secret@30 | 3100003 |
