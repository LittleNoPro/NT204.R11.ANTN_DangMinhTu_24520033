# T16 — HTTP form body decode (application/x-www-form-urlencoded)

Testcase bổ sung cho yêu cầu Decoder "HTTP URL/percent decoding và
application/x-www-form-urlencoded": ngoài URI, body POST có header
`Content-Type: application/x-www-form-urlencoded` cũng được decode
(`+` → space, `%XX` → byte UTF-8). Body raw trong `application.body` giữ
nguyên; bản decode nằm ở `decoder.body_decoded`.

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T16_Form_Body_Decode/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T16_Form_Body_Decode/input.pcap \
    --count 20 --output TEST/Bai-tap-02/T16_Form_Body_Decode/output.jsonl
```

## Input

- `input.pcap` — 4 frame HTTP POST `10.0.0.1 → 10.0.0.2:80`, khác nhau ở
  `Content-Type` và body.

## Output

- `output.jsonl` — 4 event, quan tâm `application.body` (raw) và
  `decoder.body_decoded` / `decode_method` / `decode_status`.

## Kết quả

| Frame | Content-Type | Body raw | Kết quả decode |
|---|---|---|---|
| 1 | form-urlencoded | `user=admin%27%20OR%201%3D1&pass=x` | `user=admin' OR 1=1&pass=x`, `form_urlencoded`, `ok` |
| 2 | form-urlencoded; charset=UTF-8 | `name=Nguy%E1%BB%85n+V%C4%83n+A&city=Ha+Noi` | `name=Nguyễn Văn A&city=Ha Noi`, `ok` |
| 3 | application/json | `{"q": "%27%20OR%201%3D1"}` | không decode (không phải form) → `not_applicable` |
| 4 | form-urlencoded | `user=admin&pass=secret` | không có gì để decode → `body_decoded = null`, `not_applicable` |

Vì Matching Engine (BT3) tìm content cả trong `body_decoded`, rule
`content:"' OR 1=1"` giờ bắt được SQL injection nằm trong body POST (frame 1).
