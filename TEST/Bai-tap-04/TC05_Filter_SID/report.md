# TC05 — Filter theo SID

Mục tiêu: SID bị suppress không được lưu như alert thông thường. Suppress cấu hình trong
`alert.suppress`: mỗi mục gồm `sid` và tùy chọn `src_ip` / `dst_ip` (IP hoặc CIDR) /
`protocol`; alert khớp **mọi** trường của một mục thì bị loại (giống `suppress` của Snort).

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-04/TC05_Filter_SID/gen_input.py
.venv/bin/python src/main.py -c TEST/Bai-tap-04/TC05_Filter_SID/config.json \
    -r TEST/Bai-tap-04/TC05_Filter_SID/input.pcap \
    -l TEST/Bai-tap-04/TC05_Filter_SID \
    -v \
    2> TEST/Bai-tap-04/TC05_Filter_SID/engine.log
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC05_Filter_SID/config.json \
    -l TEST/Bai-tap-04/TC05_Filter_SID \
    -a > TEST/Bai-tap-04/TC05_Filter_SID/alerts.jsonl
.venv/bin/python src/report.py -c TEST/Bai-tap-04/TC05_Filter_SID/config.json \
    -l TEST/Bai-tap-04/TC05_Filter_SID \
    -o TEST/Bai-tap-04/TC05_Filter_SID/report.json \
    > TEST/Bai-tap-04/TC05_Filter_SID/report.txt
```

## Input

- `input.pcap` — hai client cùng gửi `GET /admin/config.php` tới 192.168.1.20:80:
  10.0.0.5 (máy quét nội bộ) và 172.16.0.9.
- `test.rules` — 3 rule cùng priority 2 (HIGH), để kết quả chỉ phụ thuộc vào suppress:
  4050001 `/admin/`, 4050002 `config.php`, 4050003 `GET`.
- `config.json`:
  ```json
  "suppress": [
    {"sid": 4050001},
    {"sid": 4050002, "src_ip": "10.0.0.0/24"}
  ]
  ```
  4050001 bị tắt hoàn toàn; 4050002 chỉ bị tắt khi nguồn thuộc 10.0.0.0/24.

## Output

- `engine.log` — alert được giữ và dòng `[alert] filtered: ...` kèm mục suppress đã khớp.
- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db`.
- `report.txt`, `report.json` — báo cáo trên dữ liệu đã lưu.
- `detections.jsonl` — 6 Detection Event do Core Engine sinh (trước khi lọc).
- `fast.log`, `events.jsonl`, `flows.jsonl`, `trace.jsonl`, `rules_report.jsonl`.

## Kết quả

`[alert] {'received': 6, 'filtered': 3, 'alert': 3}`

| Nguồn | sid | Mong đợi | Thực tế |
|---|---|---|---|
| 10.0.0.5 | 4050001 | loại | `suppress {'sid': 4050001}` |
| 10.0.0.5 | 4050002 | loại (nguồn thuộc 10.0.0.0/24) | `suppress {'sid': 4050002, 'src_ip': '10.0.0.0/24'}` |
| 10.0.0.5 | 4050003 | giữ | A000001 |
| 172.16.0.9 | 4050001 | loại | `suppress {'sid': 4050001}` |
| 172.16.0.9 | 4050002 | giữ (nguồn ngoài 10.0.0.0/24) | A000002 |
| 172.16.0.9 | 4050003 | giữ | A000003 |

- SID bị suppress không có trong `alerts.jsonl`, không chiếm `alert_id` và không xuất hiện
  trong báo cáo (`Top SID` chỉ có 4050003 và 4050002). Chúng nằm ở bảng `discarded`
  (status `filtered`) của `alerts.db` để tra lại khi cần.
- Không có SID hay IP nào hard-code trong chương trình: mọi thứ đến từ `config.json`.

**Đạt.**
