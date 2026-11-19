# T09 — content có/không có nocase

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T09_Content_Nocase/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T09_Content_Nocase/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T09_Content_Nocase/test.rules \
    -l TEST/Bai-tap-03/T09_Content_Nocase \
    -v \
    2> TEST/Bai-tap-03/T09_Content_Nocase/engine.log
```

## Input

- `input.pcap` — 4 HTTP GET: `/admin`, `/ADMIN`, `/AdMiN`, `/user`.
- `test.rules` — 3090001 `content:"admin"`; 3090002 `content:"admin"; nocase`.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `detections.jsonl` — Detection Event (mỗi rule match 1 dòng); `fast.log` — alert dạng ngắn.
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Frame | Path | 3090001 (phân biệt hoa thường) | 3090002 (nocase) |
|---|---|---|---|
| 1 | `/admin` | MATCH | MATCH |
| 2 | `/ADMIN` | NO_MATCH | MATCH |
| 3 | `/AdMiN` | NO_MATCH | MATCH |
| 4 | `/user` | NO_MATCH | NO_MATCH |
