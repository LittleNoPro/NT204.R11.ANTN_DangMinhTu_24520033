# T11 — Hai content với distance/within

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-03/T11_Distance_Within/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-03/T11_Distance_Within/input.pcap \
    -n 50 \
    -s TEST/Bai-tap-03/T11_Distance_Within/test.rules \
    -l TEST/Bai-tap-03/T11_Distance_Within \
    -v \
    2> TEST/Bai-tap-03/T11_Distance_Within/engine.log
```

## Input

- `test.rules` — 3110001 `content:"user="; content:"admin"; distance:0; within:10`;
  3110002 `content:"user="; content:"admin"; distance:6`.
- `input.pcap` — 4 GET `/login?<query>` (xem bảng).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `events.jsonl` — event đã qua parse, decode, preprocess và flow tracking. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

Content thứ 2 tìm trong vùng `[cuối match trước + distance, + within)`. Nếu lần
match đầu của content 1 không thỏa, engine thử các vị trí sau (backtracking).

| Frame | Query | 3110001 (within 10) | 3110002 (distance 6) |
|---|---|---|---|
| 1 | `user=admin` | MATCH (admin ngay sau user=) | NO_MATCH (cách 0 < 6) |
| 2 | `user=xxxxxxxxxxxxadmin` | NO_MATCH (cách 12 byte) | MATCH |
| 3 | `admin=1&user=guest` | NO_MATCH (sai thứ tự) | NO_MATCH |
| 4 | `user=guest&user=admin` | MATCH với `user=` thứ 2 (offset 22 → admin@27) | MATCH với `user=` thứ 1 (admin cách 11) |
