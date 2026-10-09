# T03 — SMTP MIME decode (Base64 / Quoted-Printable)

## Cách chạy

```bash
# 1. Sinh input.pcap (10 frame, timestamp cố định)
.venv/bin/python TEST/Bai-tap-02/T03_SMTP_MIME/gen_input.py

# 2. Chạy pipeline → output.jsonl (xem terminal + file kết quả)
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T03_SMTP_MIME/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T03_SMTP_MIME/output.jsonl
```

## Input

- `input.pcap` — 10 frame SMTP `10.0.0.1:40000 → 10.0.0.2:25`,
  sinh bởi `gen_input.py`, timestamp cố định `1700000000+i`.
- 9 frame là DATA message (MIME headers + `Content-Transfer-Encoding` + body),
  1 frame là command `HELO`.

## Output

- `output.jsonl` — 10 event, quan tâm `decoder.body_decoded` /
  `decode_method` / `decode_status` / `decode_reason`.

## Kết quả

| Frame | Nội dung | Kết quả decode |
|---|---|---|
| 1 | Base64 ASCII: `SGVsbG8gV29ybGQ=` | `Hello World`, `decode_status = ok` |
| 2 | Base64 wrap 76 ký tự/dòng (RFC 2045), tiếng Việt | decode đủ câu `Chào mừng bạn đến với hệ thống IDS...` |
| 3 | QP: `=48=65=6C=6C=6F=20IDS=21` | `Hello IDS!` |
| 4 | QP soft break: `...=` cuối dòng | `Hello World` (nối 2 dòng) |
| 5 | QP trộn escape `=C3=A3` + UTF-8 literal | `Ngon ngã: tiếng Việt` |
| 6 | Base64 rác `!!! not base64 !!!` | `decode_status = error`, reason `Only base64 data is allowed`, không crash |
| 7 | Base64 hợp lệ → binary không phải UTF-8 | `decode_status = partial`, reason `invalid start byte`, không crash |
| 8 | CTE hoa thường lẫn lộn: `CONTENT-TRANSFER-ENCODING: Base64` | `Mixed Case Header`, `ok` |
| 9 | CTE không hỗ trợ: `8bit` | giữ nguyên, `not_applicable` |
| 10 | Command `HELO` (không phải DATA) | `smtp_command = HELO`, `not_applicable`, không crash |

Toàn bộ 10 event: payload/`smtp_body` raw giữ nguyên, không crash (exit 0);
frame 6 và 7 là 2 nhánh lỗi phải đánh dấu trạng thái thay vì dừng chương trình.
