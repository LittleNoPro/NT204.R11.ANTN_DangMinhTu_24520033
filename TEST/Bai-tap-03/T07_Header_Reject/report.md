# T07 — Header không match

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T07_Header_Reject/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T07_Header_Reject/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T07_Header_Reject/test.rules \
    -l TEST/Bai-tap-03/T07_Header_Reject \
    -v \
    2> TEST/Bai-tap-03/T07_Header_Reject/engine.log
```

## Input

- `input.pcap` — 1 frame 10.0.0.1:40000 → 10.0.0.2:80, payload chứa `attack`.
- `test.rules` — 6 rule đều có `content:"attack"` (có trong payload), chỉ khác header.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

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
