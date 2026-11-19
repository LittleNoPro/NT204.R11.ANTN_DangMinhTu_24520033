# TC14 — Report output

Mục tiêu: sinh được báo cáo human-readable (text) và machine-readable (JSON); báo cáo ghi
rõ khoảng thời gian, số liệu tổng quan và các nhóm thống kê bắt buộc; số liệu nhất quán
giữa hai bản và với dữ liệu trong Alert Repository.

Testcase dùng **bộ rule thật của hệ thống** (`rules/local.rules`) trên một kịch bản tấn
công nhiều giai đoạn, chạy qua toàn bộ pipeline: pcap → Detection Event → Alert → báo cáo.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC14_Report_Output/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC14_Report_Output/config.json \
    -r TEST/Bai-tap-04/TC14_Report_Output/input.pcap \
    -l TEST/Bai-tap-04/TC14_Report_Output \
    -v \
    2> TEST/Bai-tap-04/TC14_Report_Output/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC14_Report_Output/config.json \
    -l TEST/Bai-tap-04/TC14_Report_Output \
    --from 2025-11-15 --to 2025-11-15 \
    -o TEST/Bai-tap-04/TC14_Report_Output/report.json \
    > TEST/Bai-tap-04/TC14_Report_Output/report.txt
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC14_Report_Output/config.json \
    -l TEST/Bai-tap-04/TC14_Report_Output \
    --from 2025-11-15 --to 2025-11-15 \
    -a > TEST/Bai-tap-04/TC14_Report_Output/alerts.jsonl
.venv/bin/python TEST/Bai-tap-04/TC14_Report_Output/verify.py \
    > TEST/Bai-tap-04/TC14_Report_Output/verify.txt
```

## Input

- `input.pcap` — kịch bản ngày 2025-11-15 (UTC), mạng nội bộ 192.168.1.0/24:

  | Giờ | Sự kiện | Rule (local.rules) |
  |---|---|---|
  | 08:00:00–08:00:41 | 203.0.113.10 quét NULL + XMAS 5 cổng của 192.168.1.20 | 1000011, 1000012 |
  | 08:05:00–08:05:20 | 203.0.113.10 → 192.168.1.20:80: traversal `/etc/passwd`, SQL injection, XSS | 1000001, 1000004, 1000002, 1000003 |
  | 08:30:00, 08:30:30 | 198.51.100.7 → 192.168.1.21:8080: traversal hai lần | 1000001 |
  | 09:10:00, 09:10:20, 09:12:00 | 192.168.1.50 hỏi DNS `evil.xyz` | 1000020 |
  | 09:20:00 | 203.0.113.10 → 192.168.1.25:25: lệnh SMTP `EXPN` | 1000030 |

- `config.json` — nạp `../../../rules/local.rules`, `HOME_NET = 192.168.1.0/24`, ghi rõ toàn
  bộ cấu hình alert (severity map mặc định, aggregation 60 giây, SQLite) và
  `report.top_n = 5`.

## Output

- `report.txt` — báo cáo text cho người đọc.
- `report.json` — báo cáo JSON cho máy đọc.
- `alerts.jsonl` — alert trong cùng khoảng thời gian, đọc từ `alerts.db` (`report.py -a`).
- `verify.py` / `verify.txt` — tự tính lại số liệu từ `alerts.jsonl` và so với
  `report.json`; so các con số trong `report.txt` với `report.json`; kiểm tra báo cáo text
  có đủ các mục bắt buộc.
- `engine.log`, `fast.log`, `detections.jsonl`, `events.jsonl`, `flows.jsonl`,
  `trace.jsonl`, `rules_report.jsonl` — log của pipeline.

## Kết quả

`engine.log`: 20 Detection Event → `[alert] {'received': 20, 'alert': 10, 'aggregated': 10}`
(5 gói NULL scan gộp thành 1 alert, 5 gói XMAS thành 1, 2 lần traversal 08:30 thành 1, 2 truy
vấn DNS đầu thành 1; truy vấn 09:12 cách 120 giây nên là alert mới).

Phần đầu `report.txt`:

```
IDS SECURITY REPORT
Period: 2025-11-15T00:00:00Z -> 2025-11-15T23:59:59Z (UTC)
Total alerts: 10 (events: 20) | Critical: 3 | High: 5 | Medium: 2 | Low: 0
Top SID: 1000011 (5) | Top source: 203.0.113.10 (15)
```

Sau đó là đủ các mục: Severity, Top SID, Classtype, Top source IP, Top destination IP,
Transport protocol, Application protocol, Alerts per hour (08:00 → 7 alert / 16 events,
09:00 → 3 / 4).

`verify.txt`: **PASS (20/20 mục)**:
- Repository → JSON: `total_alerts` 10, `total_events` 20, phân bố severity, Top SID,
  Top source/destination IP, protocol và timeline tính lại từ `alerts.jsonl` đều khớp
  `report.json`.
- JSON → text: dòng `Total alerts`, phân bố severity, `Period`, `Top SID / Top source`
  trong `report.txt` giống `report.json`.
- `report.txt` có đủ 8 mục thống kê bắt buộc.

**Đạt.**

## Thay đổi đi kèm

Bảng trong báo cáo text tự nới độ rộng cột theo nhãn dài nhất.
`DNS query for suspicious .xyz domain` dài hơn độ rộng cố định cũ (44 ký tự) và làm lệch
cột `alerts=`. Các báo cáo của TC04–TC13 không đổi, vì nhãn của chúng ngắn hơn 44 ký tự.
