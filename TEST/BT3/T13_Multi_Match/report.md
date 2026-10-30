# T13 — Một event match đồng thời nhiều rule

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T13_Multi_Match/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T13_Multi_Match/input.pcap \
    --count 50 --output TEST/BT3/T13_Multi_Match/output.jsonl \
    --rules TEST/BT3/T13_Multi_Match/test.rules \
    --rules-report TEST/BT3/T13_Multi_Match/rules_report.jsonl \
    --alerts TEST/BT3/T13_Multi_Match/alerts.jsonl --trace TEST/BT3/T13_Multi_Match/trace.jsonl \
    2> TEST/BT3/T13_Multi_Match/engine.log
```

## Input

- `input.pcap` — 1 frame `GET /../../etc/passwd?q=<script>alert(1)</script> HTTP/1.1`.
- `test.rules` — 4 rule có content nằm trong payload + 1 rule đối chứng (`wp-login`).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| sid | Content | Kết quả |
|---|---|---|
| 3130001 | `../` | MATCH (offset 5) |
| 3130002 | `/etc/passwd` | MATCH (offset 10) |
| 3130003 | `<script` nocase | MATCH (offset 24) |
| 3130004 | `GET` depth 3 | MATCH (offset 0) |
| 3130005 | `wp-login` | NO_MATCH, `stage=content` |

`alerts.jsonl` có đủ **4 Detection Event** cho cùng `packet_id=1`, engine không dừng ở
rule đầu tiên (`matches: 4`).
