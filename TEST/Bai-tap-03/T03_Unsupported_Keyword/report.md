# T03 — Rule dùng keyword ngoài phạm vi

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T03_Unsupported_Keyword/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T03_Unsupported_Keyword/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T03_Unsupported_Keyword/test.rules \
    -l TEST/Bai-tap-03/T03_Unsupported_Keyword \
    -v \
    2> TEST/Bai-tap-03/T03_Unsupported_Keyword/engine.log
```

## Input

- `test.rules` — 9 rule đúng cú pháp Snort nhưng dùng tính năng engine chưa hỗ trợ +
  1 rule hợp lệ có `reference`/`metadata` (keyword thông tin, được bỏ qua).
- `input.pcap` — phiên HTTP 5 frame giống T02.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

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
