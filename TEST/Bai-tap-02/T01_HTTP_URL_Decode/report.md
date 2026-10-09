# T01 — HTTP URL decode

## Cách chạy

```bash
# 1. Sinh input.pcap (10 frame, timestamp cố định)
.venv/bin/python TEST/Bai-tap-02/T01_HTTP_URL_Decode/gen_input.py

# 2. Chạy pipeline → output.jsonl (xem terminal + file kết quả)
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T01_HTTP_URL_Decode/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T01_HTTP_URL_Decode/output.jsonl
```

## Input

- `input.pcap` — 10 frame TCP `10.0.0.1:40000 → 10.0.0.2:80` (HTTP GET),
  sinh bởi `gen_input.py`, timestamp cố định `1700000000+i`.

## Output

- `output.jsonl` — 10 event, quan tâm `application.path` (raw) và
  `decoder.uri_decoded` / `decode_method` / `decode_status`.

## Kết quả

| Frame | Nội dung | Kết quả decode |
|---|---|---|
| 1 | URI kiểu SQL injection: `%27%20OR%201%3D1` | `/search?q=' OR 1=1` |
| 2 | `+` trong query, `+` trong path | query → space: `/s+a?q=hello world` |
| 3 | UTF-8 tiếng Việt: `ti%E1%BA%BFng%20Vi%E1%BB%87t` | `/tim?q=tiếng Việt` |
| 4 | XSS encode `< > ( ) /`: `%3Cscript%3E...` | `/search?q=<script>alert(1)</script>` |
| 5 | Slash encoded: `/user%2Fadmin%2Fprofile` | `/user/admin/profile?role=admin` |
| 6 | Space trong path: `path%20with%20spaces` | `/path with spaces/index.html` |
| 7 | Nhiều param, `+` + UTF-8: `Nguy%E1%BB%85n+V%C4%83n+A` | `/s?name=Nguyễn Văn A&city=Ha Noi` |
| 8 | Encode cả URL: `https%3A%2F%2F...` | `/redir?url=https://example.com/?a=1` |
| 9 | `%` không hợp lệ (`%zz`) | giữ nguyên `/search?q=100%zz`, không crash, status `ok` |
| 10 | Không có encoding | `uri_decoded = null`, status `not_applicable` |

Toàn bộ 10 event: raw `application.path` giữ nguyên 100% (decoder chỉ thêm
`decoder.uri_decoded`), `decode_method = percent`, không crash (exit 0).
