# T05 — Direction -> và <>

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T05_Direction/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T05_Direction/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T05_Direction/test.rules \
    -l TEST/Bai-tap-03/T05_Direction \
    -v \
    2> TEST/Bai-tap-03/T05_Direction/engine.log
```

## Input

- `test.rules` — cùng content `HELLO`: 3050001 `10.0.0.1 any -> 10.0.0.2 80`,
  3050002 `10.0.0.1 any <> 10.0.0.2 80`, 3050003 `10.0.0.2 80 -> 10.0.0.1 any`.
- `input.pcap` — frame 1 client→server, frame 2 server→client, frame 3 host 10.0.0.3→server.

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

| Frame | Chiều | Match | Ghi chú |
|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | 3050001, 3050002 | `->` đúng chiều; `<>` khớp chiều xuôi |
| 2 | 10.0.0.2:80 → 10.0.0.1:40000 | 3050002, 3050003 | 3050001 không phải candidate (dst port 40000); `<>` khớp chiều ngược |
| 3 | 10.0.0.3:40001 → 10.0.0.2:80 | — | 3050001, 3050002 bị loại ở `stage=header` (src IP khác) |
