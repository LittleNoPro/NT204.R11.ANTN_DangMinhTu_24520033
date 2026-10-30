# T09 — content có/không có nocase

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T09_Content_Nocase/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T09_Content_Nocase/input.pcap \
    --count 50 --output TEST/BT3/T09_Content_Nocase/output.jsonl \
    --rules TEST/BT3/T09_Content_Nocase/test.rules \
    --rules-report TEST/BT3/T09_Content_Nocase/rules_report.jsonl \
    --alerts TEST/BT3/T09_Content_Nocase/alerts.jsonl --trace TEST/BT3/T09_Content_Nocase/trace.jsonl \
    2> TEST/BT3/T09_Content_Nocase/engine.log
```

## Input

- `input.pcap` — 4 HTTP GET: `/admin`, `/ADMIN`, `/AdMiN`, `/user`.
- `test.rules` — 3090001 `content:"admin"`; 3090002 `content:"admin"; nocase`.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Frame | Path | 3090001 (phân biệt hoa thường) | 3090002 (nocase) |
|---|---|---|---|
| 1 | `/admin` | MATCH | MATCH |
| 2 | `/ADMIN` | NO_MATCH | MATCH |
| 3 | `/AdMiN` | NO_MATCH | MATCH |
| 4 | `/user` | NO_MATCH | NO_MATCH |
