# T12 — flags và dsize

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T12_Flags_Dsize/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T12_Flags_Dsize/input.pcap \
    --count 50 --output TEST/BT3/T12_Flags_Dsize/output.jsonl \
    --rules TEST/BT3/T12_Flags_Dsize/test.rules \
    --rules-report TEST/BT3/T12_Flags_Dsize/rules_report.jsonl \
    --alerts TEST/BT3/T12_Flags_Dsize/alerts.jsonl --trace TEST/BT3/T12_Flags_Dsize/trace.jsonl \
    2> TEST/BT3/T12_Flags_Dsize/engine.log
```

## Input

- `test.rules` — 7 rule flags (`S`, `SA`, `S+`, `*FR`, `!A`, `0`, `FPU`), 2 rule dsize
  (`>100`, `5<>20`) và 1 rule kết hợp `flags:PA; dsize:>100`.
- `input.pcap` — 9 frame TCP (xem bảng).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

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
