# T03 — Rule dùng keyword ngoài phạm vi

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T03_Unsupported_Keyword/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T03_Unsupported_Keyword/input.pcap \
    --count 50 --output TEST/BT3/T03_Unsupported_Keyword/output.jsonl \
    --rules TEST/BT3/T03_Unsupported_Keyword/test.rules \
    --rules-report TEST/BT3/T03_Unsupported_Keyword/rules_report.jsonl \
    --alerts TEST/BT3/T03_Unsupported_Keyword/alerts.jsonl --trace TEST/BT3/T03_Unsupported_Keyword/trace.jsonl \
    2> TEST/BT3/T03_Unsupported_Keyword/engine.log
```

## Input

- `test.rules` — 9 rule đúng cú pháp Snort nhưng dùng tính năng ngoài phạm vi bài tập +
  1 rule hợp lệ có `reference`/`metadata` (keyword thông tin, được bỏ qua).
- `input.pcap` — phiên HTTP 5 frame giống T02.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Dòng | Rule | Kết quả |
|---|---|---|
| 2 | `pcre` | `unsupported`, `unsupported keyword(s) pcre` |
| 3 | `http_uri`, `byte_test` | `unsupported keyword(s) http_uri, byte_test` (liệt kê đủ) |
| 4 | `file_data` | `unsupported keyword(s) file_data` |
| 5, 6 | action `drop`, `log` | `unsupported action 'drop'` / `'log'` |
| 7 | protocol `icmp` | `unsupported protocol 'icmp'` |
| 8 | IP `2001:db8::1` | `unsupported IPv6 address` |
| 9 | `flow:only_stream` | `unsupported flow option 'only_stream'` |
| 10 | `content:!"GET"` | `unsupported negated content` |
| 11 | `reference`, `metadata` | `valid` — keyword thông tin không ảnh hưởng detection |
| — | engine | `{'valid': 1, 'unsupported': 9}`, không crash; sid 3030100 match frame 4 |
