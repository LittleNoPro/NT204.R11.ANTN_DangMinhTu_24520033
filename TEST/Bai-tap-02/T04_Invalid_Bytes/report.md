# T04 — Invalid bytes

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T04_Invalid_Bytes/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T04_Invalid_Bytes/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T04_Invalid_Bytes/output.jsonl
```

## Input

- `input.pcap` — 8 frame TCP `10.0.0.1:40000 → 10.0.0.2:8080`,
  payload mô phỏng các loại byte không phải UTF-8 hợp lệ + 1 frame UTF-8 hợp lệ.

## Output

- `output.jsonl` — 8 event, quan tâm `decoder.decode_status` / `decode_reason`.

## Kết quả

| Frame | Nội dung payload | Kết quả |
|---|---|---|
| 1 | Lone continuation byte `\x80` | `partial` — invalid start byte |
| 2 | Truncated sequence `... \xc3` (dở dang) | `partial` — unexpected end of data |
| 3 | UTF-16 BOM `\xff\xfe` | `partial` — invalid start byte |
| 4 | Overlong encoding `\xc0\xaf` | `partial` — invalid start byte |
| 5 | Surrogate half `\xed\xa0\x80` | `partial` — invalid continuation byte |
| 6 | Trộn hợp lệ + lỗi `OK\xffEND` | `partial` — invalid start byte |
| 7 | Binary ngẫu nhiên (control chars + 0x89) | `partial` — invalid start byte |
| 8 | UTF-8 hợp lệ `tiếng Việt ok` | `not_applicable` (không có gì decode) |

Toàn bộ: chương trình chạy hết 8 frame, exit 0 — packet lỗi không làm dừng
pipeline (yêu cầu chung §2); trạng thái/ lý do nằm trong `decode_status`/`decode_reason`.
