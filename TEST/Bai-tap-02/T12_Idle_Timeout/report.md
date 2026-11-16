# T12 — Idle timeout

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T12_Idle_Timeout/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-02/T12_Idle_Timeout/config.json \
    -r TEST/Bai-tap-02/T12_Idle_Timeout/input.pcap \
    -n 50 \
    -l TEST/Bai-tap-02/T12_Idle_Timeout
```

## Input

- `input.pcap` — 2 frame UDP DNS cùng 5-tuple, `pkt.time` chênh **10 giây**
  (vượt timeout UDP 5 giây trong `config.json`): query `first.example.com` @t=0, query
  `second.example.com` @t=10.

## Output

- `events.jsonl` (2 event) + `flows.jsonl` (2 flow).

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | query @t=1700000000 | tạo flow mới, `last_seen=1700000000` |
| 2 | query @t=1700000010 | gap 10s > timeout 5s → **flow 1 hết hạn bị đóng + giải phóng khỏi active table** trước khi xử lý packet mới → tạo flow thứ 2 |
| — | flow 1 | `end_reason=timeout` (xuất ra file khi bị loại) |
| — | flow 2 | `end_reason=eof`, `packet_count=1` |
