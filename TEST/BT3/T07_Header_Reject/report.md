# T07 — Header không match

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T07_Header_Reject/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T07_Header_Reject/input.pcap \
    --count 50 --output TEST/BT3/T07_Header_Reject/output.jsonl \
    --rules TEST/BT3/T07_Header_Reject/test.rules \
    --rules-report TEST/BT3/T07_Header_Reject/rules_report.jsonl \
    --alerts TEST/BT3/T07_Header_Reject/alerts.jsonl --trace TEST/BT3/T07_Header_Reject/trace.jsonl \
    2> TEST/BT3/T07_Header_Reject/engine.log
```

## Input

- `input.pcap` — 1 frame 10.0.0.1:40000 → 10.0.0.2:80, payload chứa `attack`.
- `test.rules` — 6 rule đều có `content:"attack"` (có trong payload), chỉ khác header.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| sid | Header khác ở | Kết quả trong `trace.jsonl` |
|---|---|---|
| 3070001 | dst IP 192.168.1.20 | candidate → `NO_MATCH`, `stage=header`, `reason="address/port mismatch"` |
| 3070002 | src 172.16.0.0/12 | `stage=header` |
| 3070003 | src port 1:1024 | `stage=header` |
| 3070004 | protocol udp | không phải candidate (Indexer loại theo protocol) |
| 3070005 | dst port 8080 | không phải candidate (Indexer loại theo port) |
| 3070100 | đối chứng, header khớp | `MATCH`, content `attack` tại offset 5 |

Rule bị loại bởi header không chạy tới bước content dù content có trong payload
(thống kê `rejected_header: 3`, không có `rejected_content`).
