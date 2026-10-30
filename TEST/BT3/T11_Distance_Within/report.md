# T11 — Hai content với distance/within

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T11_Distance_Within/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T11_Distance_Within/input.pcap \
    --count 50 --output TEST/BT3/T11_Distance_Within/output.jsonl \
    --rules TEST/BT3/T11_Distance_Within/test.rules \
    --rules-report TEST/BT3/T11_Distance_Within/rules_report.jsonl \
    --alerts TEST/BT3/T11_Distance_Within/alerts.jsonl --trace TEST/BT3/T11_Distance_Within/trace.jsonl \
    2> TEST/BT3/T11_Distance_Within/engine.log
```

## Input

- `test.rules` — 3110001 `content:"user="; content:"admin"; distance:0; within:10`;
  3110002 `content:"user="; content:"admin"; distance:6`.
- `input.pcap` — 4 GET `/login?<query>` (xem bảng).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

Content thứ 2 tìm trong vùng `[cuối match trước + distance, + within)`. Nếu lần
match đầu của content 1 không thỏa, engine thử các vị trí sau (backtracking).

| Frame | Query | 3110001 (within 10) | 3110002 (distance 6) |
|---|---|---|---|
| 1 | `user=admin` | MATCH (admin ngay sau user=) | NO_MATCH (cách 0 < 6) |
| 2 | `user=xxxxxxxxxxxxadmin` | NO_MATCH (cách 12 byte) | MATCH |
| 3 | `admin=1&user=guest` | NO_MATCH (sai thứ tự) | NO_MATCH |
| 4 | `user=guest&user=admin` | MATCH với `user=` thứ 2 (offset 22 → admin@27) | MATCH với `user=` thứ 1 (admin cách 11) |
