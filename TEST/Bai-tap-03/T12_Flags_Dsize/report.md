# T12 — flags và dsize

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T12_Flags_Dsize/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T12_Flags_Dsize/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T12_Flags_Dsize/test.rules \
    -l TEST/Bai-tap-03/T12_Flags_Dsize \
    -v \
    2> TEST/Bai-tap-03/T12_Flags_Dsize/engine.log
```

## Input

- `test.rules` — 7 rule flags (`S`, `SA`, `S+`, `*FR`, `!A`, `0`, `FPU`), 2 rule dsize
  (`>100`, `5<>20`) và 1 rule kết hợp `flags:PA; dsize:>100`.
- `input.pcap` — 9 frame TCP (xem bảng).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `detections.jsonl` — Detection Event (mỗi rule match 1 dòng); `fast.log` — alert dạng ngắn.
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

Ngữ nghĩa flags: không modifier = đúng bộ flag; `+` = có đủ các flag này (cho phép thêm);
`*` = có ít nhất 1; `!` = không có flag nào; `0` = không có flag.

| Frame | Flags / dsize | Match (3120xxx) |
|---|---|---|
| 1 | S / 0 | 1 (S), 3 (S+), 5 (!A) |
| 2 | SA / 0 | 2 (SA), 3 (S+) |
| 3 | A / 0 | — |
| 4 | PA / 10 | 9 (dsize 5..20) |
| 5 | PA / 150 | 8 (dsize >100), 10 (PA + dsize >100) |
| 6 | F / 0 | 4 (*FR), 5 (!A) |
| 7 | RA / 0 | 4 (*FR) |
| 8 | 0 / 0 | 5 (!A), 6 (0) |
| 9 | FPU / 0 | 4 (*FR), 5 (!A), 7 (FPU) |

Rule không thỏa bị loại ở `stage=flags` hoặc `stage=dsize` trong `trace.jsonl`.
