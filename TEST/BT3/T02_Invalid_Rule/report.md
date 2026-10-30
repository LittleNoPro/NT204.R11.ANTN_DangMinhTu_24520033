# T02 — Rule sai cú pháp

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T02_Invalid_Rule/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T02_Invalid_Rule/input.pcap \
    --count 50 --output TEST/BT3/T02_Invalid_Rule/output.jsonl \
    --rules TEST/BT3/T02_Invalid_Rule/test.rules \
    --rules-report TEST/BT3/T02_Invalid_Rule/rules_report.jsonl \
    --alerts TEST/BT3/T02_Invalid_Rule/alerts.jsonl --trace TEST/BT3/T02_Invalid_Rule/trace.jsonl \
    2> TEST/BT3/T02_Invalid_Rule/engine.log
```

## Input

- `test.rules` — 14 rule sai mỗi rule một lỗi + 1 rule hợp lệ ở cuối (sid 3020100).
- `input.pcap` — phiên HTTP 5 frame: SYN → SYN/ACK → ACK → GET → 200 OK.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Dòng | Lỗi | `reason` |
|---|---|---|
| 2 | thiếu `( options )` | `missing '( options )'` |
| 3 | header 6 trường | `header needs 7 fields, got 6` |
| 4 | direction `<-` | `invalid direction '<-'` |
| 5 | IP `300.1.1.1` | `invalid IP address '300.1.1.1'` |
| 6 | port 70000 | `invalid port '70000'` |
| 7 | range `100:50` | `invalid port range '100:50'` |
| 8 | thiếu sid | `missing sid` |
| 9 | `sid:abc` | `sid must be an integer, got 'abc'` |
| 10 | nháy chưa đóng | `unterminated quoted string in options` |
| 11 | `nocase` đứng trước mọi content | `nocase without preceding content` |
| 12 | `depth:2` < độ dài content 4 | `depth 2 smaller than content length 4` |
| 13 | `flags:SZ` | `invalid TCP flag(s) 'Z'` |
| 14 | `flags` trong rule udp | `flags requires protocol tcp` |
| 15 | `$UNKNOWN_NET` | `undefined variable $UNKNOWN_NET` |
| — | engine | `{'valid': 1, 'invalid': 14}`; vẫn xử lý đủ 5 packet, rule 3020100 match frame 4 (GET) → 1 dòng trong `alerts.jsonl` |
