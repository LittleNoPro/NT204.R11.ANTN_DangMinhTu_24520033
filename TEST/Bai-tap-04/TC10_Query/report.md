# TC10 — Query

Mục tiêu: truy vấn Alert Repository đúng theo khoảng thời gian kết hợp ít nhất một tiêu
chí khác (severity, SID, source/destination IP, protocol).

Truy vấn dùng `report.py -a`: in các Alert Object khớp điều kiện dưới dạng JSON Lines.
Một alert khớp khoảng `[--from, --to]` nếu khoảng `first_seen → last_seen` của nó giao với
khoảng đó. `--to` không ghi giây được tính tới hết phút/ngày đó
(`--to 2025-11-15T01:59` là tới 01:59:59).

## Cách chạy

Nạp 8 Detection Event vào Alert Repository (chế độ `-D`, không cần pcap):

```bash
.venv/bin/python TEST/Bai-tap-04/TC10_Query/gen_input.py
.venv/bin/python src/main.py -c rules/engine.json \
    -D TEST/Bai-tap-04/TC10_Query/input.jsonl \
    -l TEST/Bai-tap-04/TC10_Query \
    -v \
    2> TEST/Bai-tap-04/TC10_Query/engine.log
```

Các truy vấn:

```bash
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 \
    > TEST/Bai-tap-04/TC10_Query/q1_time.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 --severity HIGH \
    > TEST/Bai-tap-04/TC10_Query/q2_time_severity.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 --sid 4100001 \
    > TEST/Bai-tap-04/TC10_Query/q3_time_sid.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 --src 10.0.0.5 \
    > TEST/Bai-tap-04/TC10_Query/q4_time_src.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 --dst 192.168.1.53 --protocol udp \
    > TEST/Bai-tap-04/TC10_Query/q5_time_dst_protocol.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-15 --to 2025-11-15 --sid 4100001 \
    > TEST/Bai-tap-04/TC10_Query/q6_day_sid.jsonl
.venv/bin/python src/report.py -c rules/engine.json -l TEST/Bai-tap-04/TC10_Query -a \
    --from 2025-11-16 \
    > TEST/Bai-tap-04/TC10_Query/q7_empty.jsonl
```

## Input

`input.jsonl` (sinh bởi `gen_input.py`), ngày 2025-11-15, giờ UTC:

| alert_id | Thời điểm | sid | severity | protocol | src → dst |
|---|---|---|---|---|---|
| A000001 | 00:10 | 4100001 | CRITICAL | TCP | 10.0.0.5 → 192.168.1.20:80 |
| A000002 | 00:50 | 4100002 | HIGH | TCP | 10.0.0.6 → 192.168.1.20:80 |
| A000003 | 01:05 | 4100001 | CRITICAL | TCP | 10.0.0.5 → 192.168.1.21:80 |
| A000004 | 01:20 | 4100002 | HIGH | TCP | 10.0.0.7 → 192.168.1.20:80 |
| A000005 | 01:35 | 4100003 | HIGH | UDP | 10.0.0.8 → 192.168.1.53:53 |
| A000006 | 01:50 | 4100004 | MEDIUM | TCP | 10.0.0.5 → 192.168.1.20:22 |
| A000007 | 02:15 | 4100003 | HIGH | UDP | 10.0.0.8 → 192.168.1.53:53 |
| A000008 | 03:00 | 4100001 | CRITICAL | TCP | 10.0.0.9 → 192.168.1.20:80 |

`engine.log`: `[alert] {'received': 8, 'alert': 8}`.

## Output

- `q1_time.jsonl` … `q7_empty.jsonl` — kết quả từng truy vấn (Alert Object đầy đủ).
- `engine.log`, `fast.log` — 8 alert khi nạp.

## Kết quả

| Truy vấn | Điều kiện | Mong đợi | Thực tế |
|---|---|---|---|
| q1 | 01:00–01:59 | A3, A4, A5, A6 | A000003 A000004 A000005 A000006 |
| q2 | 01:00–01:59 + severity HIGH | A4, A5 | A000004 A000005 |
| q3 | 01:00–01:59 + sid 4100001 | A3 | A000003 |
| q4 | 01:00–01:59 + src 10.0.0.5 | A3, A6 | A000003 A000006 |
| q5 | 01:00–01:59 + dst 192.168.1.53 + protocol UDP | A5 | A000005 |
| q6 | cả ngày 2025-11-15 + sid 4100001 | A1, A3, A8 | A000001 A000003 A000008 |
| q7 | từ 2025-11-16 (không có dữ liệu) | rỗng | rỗng, exit code 0 |

- Lọc thời gian loại đúng alert ngoài khoảng: A000002 (00:50) và A000007 (02:15) không
  có trong q1.
- `--protocol udp` viết thường vẫn khớp (chuẩn hóa thành `UDP`).
- `--to 2025-11-15` (chỉ có ngày) được tính tới hết ngày, nên q6 lấy được A000008 lúc
  03:00.

**Đạt.**
