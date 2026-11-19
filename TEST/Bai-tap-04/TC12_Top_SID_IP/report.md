# TC12 — Top SID/IP

Mục tiêu: xếp hạng Top-N SID, source IP và destination IP đúng; N lấy từ cấu hình
(`report.top_n`) và ghi đè được bằng `-n`.

Quy tắc xếp hạng: theo `events` (số Detection Event thật, sau aggregation là tổng `count`)
giảm dần. Hòa thì xét số `alerts` giảm dần, rồi tới giá trị (SID/IP) tăng dần.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC12_Top_SID_IP/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC12_Top_SID_IP/config.json \
    -D TEST/Bai-tap-04/TC12_Top_SID_IP/input.jsonl \
    -l TEST/Bai-tap-04/TC12_Top_SID_IP \
    -v \
    2> TEST/Bai-tap-04/TC12_Top_SID_IP/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC12_Top_SID_IP/config.json \
    -l TEST/Bai-tap-04/TC12_Top_SID_IP \
    -o TEST/Bai-tap-04/TC12_Top_SID_IP/report_top3.json \
    > TEST/Bai-tap-04/TC12_Top_SID_IP/report_top3.txt
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC12_Top_SID_IP/config.json \
    -l TEST/Bai-tap-04/TC12_Top_SID_IP \
    -n 5 \
    -o TEST/Bai-tap-04/TC12_Top_SID_IP/report_top5.json \
    > TEST/Bai-tap-04/TC12_Top_SID_IP/report_top5.txt
```

## Input

- `input.jsonl` (sinh bởi `gen_input.py`): 17 Detection Event ngày 2025-11-15:

  | sid | Event | Nhóm (window 60 giây) | src → dst |
  |---|---|---|---|
  | 4120001 | 6 event trong 50 giây | 1 alert | 10.0.0.5 → 192.168.1.20 |
  | 4120002 | 4 event cách nhau 1000 giây | 4 alert | 10.0.0.6 → 192.168.1.20 |
  | 4120003 | 2 cặp event, mỗi cặp cách 10 giây | 2 alert | 10.0.0.7 → 192.168.1.21 |
  | 4120004 | 2 event | 2 alert | 10.0.0.8 → .22, 10.0.0.5 → .22 |
  | 4120005 | 1 event | 1 alert | 10.0.0.9 → 192.168.1.23 |

- `config.json` — `"report": {"top_n": 3}`, aggregation 60 giây.

Mong đợi (tính tay):

| Hạng | SID | Source IP | Destination IP |
|---|---|---|---|
| 1 | 4120001 (6 events / 1 alert) | 10.0.0.5 (7 / 2) | 192.168.1.20 (10 / 5) |
| 2 | 4120002 (4 / 4) | 10.0.0.6 (4 / 4) | 192.168.1.21 (4 / 2) |
| 3 | 4120003 (4 / 2) | 10.0.0.7 (4 / 2) | 192.168.1.22 (2 / 2) |
| 4 | 4120004 (2 / 2) | 10.0.0.8 (1 / 1) | 192.168.1.23 (1 / 1) |
| 5 | 4120005 (1 / 1) | 10.0.0.9 (1 / 1) | — |

## Output

- `engine.log` — `[alert] {'received': 17, 'alert': 10, 'aggregated': 7}`.
- `report_top3.txt` / `.json` — Top-N với `top_n = 3` từ cấu hình.
- `report_top5.txt` / `.json` — Top-N với `-n 5` ghi đè cấu hình.
- `fast.log` — 10 alert.

## Kết quả

`report_top3.txt`:

```
Top SID
  4120001  Brute force burst      alerts=1     events=6
  4120002  SQL injection          alerts=4     events=4
  4120003  Directory traversal    alerts=2     events=4

Top source IP
  10.0.0.5                        alerts=2     events=7
  10.0.0.6                        alerts=4     events=4
  10.0.0.7                        alerts=2     events=4

Top destination IP
  192.168.1.20                    alerts=5     events=10
  192.168.1.21                    alerts=2     events=4
  192.168.1.22                    alerts=2     events=2
```

- Khớp bảng tính tay. Bảng chỉ có 3 dòng theo `top_n = 3`; `report_top5.txt` có đủ
  5 SID, 5 source IP và 4 destination IP (chỉ có 4 dst), đúng thứ tự.
- 4120001 đứng đầu dù chỉ có 1 alert, vì xếp theo events (6) chứ không theo số alert.
- Hòa 4 events giữa 4120002 và 4120003 (và giữa 10.0.0.6 và 10.0.0.7) được phân định
  bằng số alert: 4 > 2.
- 10.0.0.5 cộng dồn events từ hai SID (6 của 4120001 + 1 của 4120004 = 7).

**Đạt.**
