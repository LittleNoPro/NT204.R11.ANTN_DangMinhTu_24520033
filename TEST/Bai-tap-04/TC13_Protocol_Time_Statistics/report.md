# TC13 — Protocol/time statistics

Mục tiêu: báo cáo thống kê đúng theo transport protocol, application protocol và theo
thời gian (alerts per hour / per minute).

Testcase chạy qua toàn bộ pipeline từ pcap, nên `protocol` và `application_protocol` của
alert do Parser nhận diện thật, không phải giá trị gán tay.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/config.json \
    -r TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/input.pcap \
    -l TEST/Bai-tap-04/TC13_Protocol_Time_Statistics \
    -v \
    2> TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/config.json \
    -l TEST/Bai-tap-04/TC13_Protocol_Time_Statistics \
    -o TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/report_hour.json \
    > TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/report_hour.txt
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/config.json \
    -l TEST/Bai-tap-04/TC13_Protocol_Time_Statistics \
    --from 2025-11-15T01:00 --to 2025-11-15T01:59 --bucket minute \
    -o TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/report_minute.json \
    > TEST/Bai-tap-04/TC13_Protocol_Time_Statistics/report_minute.txt
```

## Input

- `input.pcap` — 8 tấn công ngày 2025-11-15 (UTC), mỗi tấn công một packet:

  | Giờ | Transport / App | Luồng | Rule |
  |---|---|---|---|
  | 00:05 | TCP / HTTP | 10.0.0.5 → 192.168.1.20:80 | 4130001 `../` |
  | 00:20 | TCP / HTTP | 10.0.0.5 → 192.168.1.20:80 | 4130001 |
  | 00:30 | UDP / DNS | 10.0.0.7 → 192.168.1.53:53 | 4130002 `malware` |
  | 01:10 | TCP / HTTP | 10.0.0.6 → 192.168.1.20:80 | 4130001 |
  | 01:15 | TCP / SMTP | 10.0.0.8 → 192.168.1.25:25 | 4130003 `EICAR-STANDARD` |
  | 01:40 | UDP / DNS | 10.0.0.7 → 192.168.1.53:53 | 4130002 |
  | 02:15 | UDP / DNS | 10.0.0.9 → 192.168.1.53:53 | 4130002 |
  | 02:50 | TCP / không có | 10.0.0.10 → 192.168.1.30:4444 | 4130004 `cmd.exe` |

- `test.rules` — 4 rule ở trên. `config.json` — cấu hình alert mặc định (aggregation
  60 giây; không có event nào bị gộp vì các event cùng khóa cách nhau ≥ 15 phút).

Mong đợi: TCP 5, UDP 3; HTTP 3, DNS 3, SMTP 1, không có protocol ứng dụng 1; theo giờ
00:00 → 3, 01:00 → 3, 02:00 → 2; trong 01:00–01:59 theo phút 01:10, 01:15, 01:40 mỗi
mốc 1.

## Output

- `engine.log`, `fast.log` — 8 alert, `[alert] {'received': 8, 'alert': 8}`.
- `report_hour.txt` / `.json` — báo cáo toàn bộ dữ liệu, timeline theo giờ.
- `report_minute.txt` / `.json` — báo cáo 01:00–01:59, timeline theo phút.
- `detections.jsonl`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`report_hour.txt` (không truyền `--from/--to`, nên Period lấy theo dữ liệu):

```
Period: 2025-11-15T00:05:00Z -> 2025-11-15T02:50:00Z (UTC)
Total alerts: 8 (events: 8) | Critical: 4 | High: 4 | Medium: 0 | Low: 0

Transport protocol
  TCP           alerts=5     events=5
  UDP           alerts=3     events=3

Application protocol
  DNS           alerts=3     events=3
  HTTP          alerts=3     events=3
  SMTP          alerts=1     events=1
  none          alerts=1     events=1

Alerts per hour
  2025-11-15T00:00:00Z     alerts=3     events=3
  2025-11-15T01:00:00Z     alerts=3     events=3
  2025-11-15T02:00:00Z     alerts=2     events=2
```

`report_minute.txt` (01:00–01:59, `--bucket minute`):

```
Transport protocol
  TCP           alerts=2     events=2
  UDP           alerts=1     events=1

Application protocol
  DNS / HTTP / SMTP        mỗi loại alerts=1     events=1

Alerts per minute
  2025-11-15T01:10:00Z     alerts=1     events=1
  2025-11-15T01:15:00Z     alerts=1     events=1
  2025-11-15T01:40:00Z     alerts=1     events=1
```

- Thống kê protocol và thời gian khớp bảng input ở cả hai báo cáo.
- Alert TCP cổng 4444 không có protocol ứng dụng được gom vào nhóm `none`.
- Tổng mỗi nhóm thống kê (transport, application, timeline) đều bằng `Total alerts`.

**Đạt.**
