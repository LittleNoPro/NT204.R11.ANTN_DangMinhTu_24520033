# TC03 — Event thiếu trường

Mục tiêu: Detection Event thiếu hoặc sai trường không làm chương trình crash; event bị
từ chối (rejected) hoặc tạo alert một phần (partial) kèm lý do rõ ràng.

Core Engine luôn sinh Detection Event đủ trường, nên testcase đưa Detection Event hỏng vào
**trực tiếp** Alert Module bằng chế độ `-D` (đọc Detection Event dạng JSON Lines, bỏ qua
phần bắt packet và so rule).

## Cách chạy

```bash
.venv/bin/python src/main.py -c rules/engine.json \
    -D TEST/Bai-tap-04/TC03_Missing_Field/input.jsonl \
    -l TEST/Bai-tap-04/TC03_Missing_Field \
    -v \
    2> TEST/Bai-tap-04/TC03_Missing_Field/engine.log
.venv/bin/python src/report.py -c rules/engine.json \
    -l TEST/Bai-tap-04/TC03_Missing_Field \
    -a > TEST/Bai-tap-04/TC03_Missing_Field/alerts.jsonl
```

## Input

`input.jsonl`, 9 dòng:

| Dòng | Nội dung | Mong đợi |
|---|---|---|
| 1 | Event đầy đủ (đối chứng) | alert, `status=ok` |
| 2 | Thiếu `sid` | rejected |
| 3 | Thiếu `timestamp` | rejected |
| 4 | `src_ip = "10.0.0.300"` | rejected |
| 5 | Thiếu `protocol` | rejected |
| 6 | `priority = "high"`, `src_port = 70000` (trường phụ sai) | alert, `status=partial` |
| 7 | Chỉ có trường bắt buộc, `timestamp` dạng ISO 8601 | alert, `status=ok` |
| 8 | `this is not json {` | rejected |
| 9 | `[1, 2, 3]` (JSON nhưng không phải object) | rejected |

Trường bắt buộc: `timestamp`, `sid`, `src_ip`, `dst_ip`, `protocol`. Thiếu hoặc sai một
trong các trường này thì event bị từ chối. Trường phụ sai thì bị bỏ (`null`) và alert vẫn
được tạo.

## Output

- `engine.log` — mỗi alert một dòng, mỗi event bị từ chối có dòng `[alert] rejected: <lý do>`
  (do `-v`), cuối cùng là thống kê.
- `alerts.jsonl` — Alert Object đọc lại từ `alerts.db`. Event bị từ chối nằm ở bảng
  `discarded` của `alerts.db`, không lẫn với alert.
- `fast.log` — alert dạng ngắn.

## Kết quả

Chương trình chạy hết 9 dòng, exit code 0:
`[alert] {'received': 9, 'alert': 3, 'rejected': 6}`.

| Dòng | Kết quả | Lý do / ghi chú |
|---|---|---|
| 1 | A000001, ok | CRITICAL (priority 1) |
| 2 | rejected | `sid thiếu hoặc sai: None` |
| 3 | rejected | `timestamp thiếu hoặc sai: None` |
| 4 | rejected | `IP thiếu hoặc sai: src_ip='10.0.0.300', dst_ip='192.168.1.20'` |
| 5 | rejected | `protocol thiếu hoặc sai: None` |
| 6 | A000002, **partial** | `reason = "bỏ trường sai: priority='high', src_port=70000"`; priority null → LOW; `tcp` chuẩn hóa thành `TCP` |
| 7 | A000003, ok | `msg` mặc định `sid:4030007`, severity LOW; ISO `2025-11-15T00:00:06Z` → epoch 1763164806.0 |
| 8 | rejected | `detection event không phải object JSON (str)` |
| 9 | rejected | `detection event không phải object JSON (list)` |

Event bị từ chối không chiếm `alert_id`: 3 alert hợp lệ có ID liên tục A000001–A000003.
File input không tồn tại cũng không gây traceback:
`[detections] không đọc được /nonexistent: No such file or directory`.

**Đạt.**
