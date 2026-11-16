# T10 — offset/depth

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T10_Offset_Depth/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T10_Offset_Depth/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T10_Offset_Depth/test.rules \
    -l TEST/Bai-tap-03/T10_Offset_Depth \
    -v \
    2> TEST/Bai-tap-03/T10_Offset_Depth/engine.log
```

## Input

- `test.rules` — 3100001 `GET` offset 0 depth 3; 3100002 `passwd` offset 4 depth 20
  (vùng byte 4–23); 3100003 `secret` offset 30.
- `input.pcap` — 5 payload đặt pattern trong/ngoài vùng.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Frame | Payload | Vị trí pattern | Match |
|---|---|---|---|
| 1 | `GET /etc/passwd ...` | GET@0, passwd@9 | 3100001, 3100002 |
| 2 | `POST /GET ...` | GET@6 (ngoài depth 3) | — |
| 3 | `GET /aaaa…a/passwd` | GET@0, passwd@27 (ngoài 4–23) | 3100001 |
| 4 | `secret token at ...` | secret@0 (trước offset 30) | — |
| 5 | `"x"*30 + "secret"` | secret@30 | 3100003 |
