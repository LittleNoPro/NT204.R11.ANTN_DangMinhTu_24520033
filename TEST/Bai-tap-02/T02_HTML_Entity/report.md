# T02 — HTML entity decode

## Cách chạy

```bash
# 1. Sinh input.pcap (10 frame, timestamp cố định)
.venv/bin/python TEST/Bai-tap-02/T02_HTML_Entity/gen_input.py

# 2. Chạy pipeline → output.jsonl (xem terminal + file kết quả)
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T02_HTML_Entity/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T02_HTML_Entity/output.jsonl
```

## Input

- `input.pcap` — 10 frame HTTP response `10.0.0.2:80 → 10.0.0.1:40000`,
  body là HTML entity, sinh bởi `gen_input.py`, timestamp cố định `1700000000+i`.

## Output

- `output.jsonl` — 10 event, quan tâm `application.body` (raw) và
  `decoder.text_decoded` / `decode_method` / `decode_status`.

## Kết quả

| Frame | Nội dung | Kết quả decode |
|---|---|---|
| 1 | XSS encode thẻ: `&lt;script&gt;alert(document.cookie)&lt;/script&gt;` | `<script>alert(document.cookie)</script>` |
| 2 | Entity kép `x &amp;lt; y` (decode 1 lần, không đệ quy) | `x &lt; y` |
| 3 | Decimal numeric: `&#60;b&#62;bold&#60;/b&#62;` | `<b>bold</b>` |
| 4 | Hex numeric: `&#x3C;img onerror&#x3D;x&#x3E;` | `<img onerror=x>` |
| 5 | Entity nháy: `&quot;hello&#39;world&quot;` | `"hello'world"` |
| 6 | `a&nbsp;b` | `a` + U+00A0 (space không ngắt) + `b` |
| 7 | Decimal numeric tiếng Việt: `Ti&#7871;ng Vi&#7879;t` | `Tiếng Việt` |
| 8 | Text thuần, không entity | `text_decoded = null`, status `not_applicable` |
| 9 | Entity lạ `&xyz;` | giữ nguyên, không crash, status `not_applicable` |
| 10 | Mixed: tag thật + entity: `<p>Value: &lt;script&gt;</p>` | `<p>Value: <script></p>` (tag `<p>` giữ nguyên) |

Toàn bộ 10 event: raw `application.body` giữ nguyên 100%, `decode_method =
html_entity`, `decode_status = ok` (frame 8, 9 không có gì để decode),
không crash (exit 0).
