# T13 — Một event match đồng thời nhiều rule

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T13_Multi_Match/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T13_Multi_Match/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T13_Multi_Match/test.rules \
    -l TEST/Bai-tap-03/T13_Multi_Match \
    -v \
    2> TEST/Bai-tap-03/T13_Multi_Match/engine.log
```

## Input

- `input.pcap` — 1 frame `GET /../../etc/passwd?q=<script>alert(1)</script> HTTP/1.1`.
- `test.rules` — 4 rule có content nằm trong payload + 1 rule đối chứng (`wp-login`).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `detections.jsonl` — Detection Event (mỗi rule match 1 dòng); `fast.log` — alert dạng ngắn.
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| sid | Content | Kết quả |
|---|---|---|
| 3130001 | `../` | MATCH (offset 5) |
| 3130002 | `/etc/passwd` | MATCH (offset 10) |
| 3130003 | `<script` nocase | MATCH (offset 24) |
| 3130004 | `GET` depth 3 | MATCH (offset 0) |
| 3130005 | `wp-login` | NO_MATCH, `stage=content` |

`detections.jsonl` có đủ **4 Detection Event** cho cùng `packet_id=1`, engine không dừng ở
rule đầu tiên (`matches: 4`).
