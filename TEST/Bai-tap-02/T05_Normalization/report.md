# T05 — Normalization

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T05_Normalization/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T05_Normalization/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T05_Normalization/output.jsonl
```

## Input

- `input.pcap` — 8 frame: 6 HTTP request với host/path/header khác format,
  1 DNS query hoa + trailing dot, 1 HTTP qua IPv6 — sinh bởi `gen_input.py`.

## Output

- `output.jsonl` — 8 event, quan tâm `preprocess.normalized` + `preprocess_status`.

## Kết quả

| Frame | Nội dung (raw) | Kết quả sau normalize |
|---|---|---|
| 1 | `Host: ExAmPlE.CoM.` | `host = example.com` (lowercase, bỏ dấu `.` cuối) |
| 2 | `Host: EXAMPLE.com:8080` | `host = example.com` (bỏ port) |
| 3 | `Host: bad_host..double..dot` | `partial` + `reason: invalid host` (đúng regex host) |
| 4 | `/api//v1/./users` | `path = /api/v1/users` (gộp `//`, bỏ `.`) |
| 5 | `/caf%C3%A9/menu` | `path = /café/menu` (percent-decode trong normalize) |
| 6 | `User-Agent` mixed case | `header_names = [host, user_agent]` (lowercase, sorted) |
| 7 | DNS `WIKIPEDIA.ORG.` | `host = wikipedia.org` (map query_name, lowercase) |
| 8 | IPv6 `2001:0DB8:...:0001` | `src_ip` compressed, `host = example.com` |

Mọi event có `preprocess_status` (`valid`/`partial`), `processing_action`,
`normalized.timestamp` là float — representation đầu ra đồng nhất giữa các
protocol khác nhau (HTTP/DNS, IPv4/IPv6).
