# T06 — Indexer với ip, tcp, udp và any

## Cách chạy

```bash
.venv/bin/python TEST/BT3/T06_Indexer/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/BT3/T06_Indexer/input.pcap \
    --count 50 --output TEST/BT3/T06_Indexer/output.jsonl \
    --rules TEST/BT3/T06_Indexer/test.rules \
    --rules-report TEST/BT3/T06_Indexer/rules_report.jsonl \
    --alerts TEST/BT3/T06_Indexer/alerts.jsonl --trace TEST/BT3/T06_Indexer/trace.jsonl \
    2> TEST/BT3/T06_Indexer/engine.log
```

## Input

- `test.rules` — 9 rule không có content: `ip any`, tcp dst 80, tcp dst 22, tcp any,
  tcp src 80, udp dst 53, udp any, tcp `<> 25`, tcp dst range 1000:2000.
- `input.pcap` — 7 frame (xem bảng).

## Output

- `rules_report.jsonl` — Internal Rule Object + `status`/`reason` của từng rule.
- `alerts.jsonl` — Detection Event (mỗi rule match 1 dòng).
- `trace.jsonl` — mỗi event: `candidates` (sid lấy từ Indexer) và `results` (`MATCH`/`NO_MATCH` + `stage` bị loại).
- `output.jsonl` — event của pipeline BT1–BT2. `engine.log` — cảnh báo khi nạp rule + thống kê engine.

## Kết quả

Cách index: rule `ip` áp dụng mọi packet IPv4; rule tcp/udp chia bảng theo protocol,
port liệt kê được → bảng `dst`/`src`/`either` (`<>`), any/range/phủ định → `generic`.

| Frame | Packet | `candidates` (3060xxx) | Match |
|---|---|---|---|
| 1 | TCP 40000 → 80 | 1, 2, 4, 9 | 1, 2, 4 |
| 2 | TCP 80 → 40000 | 1, 4, 5, 9 | 1, 4, 5 |
| 3 | TCP 40002 → 22 | 1, 3, 4, 9 | 1, 3, 4 |
| 4 | UDP 51000 → 53 | 1, 6, 7 | 1, 6, 7 |
| 5 | UDP 51001 → 123 | 1, 7 | 1, 7 |
| 6 | TCP 25 → 50000 | 1, 4, 8, 9 | 1, 4, 8 (`<>` tra theo src port) |
| 7 | TCP 40003 → 1500 | 1, 4, 9 | 1, 4, 9 |

- Rule udp không bao giờ là candidate của packet TCP và ngược lại; rule port 22/53/80 chỉ
  xuất hiện khi port khớp.
- Rule range (3060009) nằm ở `generic` nên luôn là candidate của TCP; bị loại ở
  `stage=header` khi port ngoài 1000–2000 (frame 1, 2, 3, 6).
- Thống kê: 7 event, 24 candidate (so với 63 nếu duyệt toàn bộ 9 rule × 7 event).
