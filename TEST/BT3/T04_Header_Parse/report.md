# T04 — Parse header TCP + any/IP/CIDR + port/range

## Cách chạy

```bash
.venv/bin/python src/main.py --check-rules \
    --rules TEST/BT3/T04_Header_Parse/test.rules \
    --rules-report TEST/BT3/T04_Header_Parse/rules_report.jsonl 2> TEST/BT3/T04_Header_Parse/engine.log
```

## Input

- `test.rules` — 8 rule phủ các dạng address/port: any, single IP, CIDR, range đóng/mở,
  list, phủ định `!`, biến Snort (`$HOME_NET`, `$HTTP_PORTS`), `<>`.

## Output

- `rules_report.jsonl` — Internal Rule Object của 8 rule.

## Kết quả

| sid | Header | Internal Rule Object (rút gọn) |
|---|---|---|
| 3040001 | `tcp any any -> any any` | 4 phía đều `{"any": true}` |
| 3040002 | `10.0.0.1 any -> 192.168.1.20 80` | `nets=["10.0.0.1/32"]`, `dst nets=["192.168.1.20/32"]`, `dst ranges=[[80,80]]` |
| 3040003 | `10.0.0.0/8 any -> 192.168.1.0/24 1:1024` | CIDR giữ nguyên, `ranges=[[1,1024]]` |
| 3040004 | `any 1024: -> any :1023` | `src [[1024,65535]]`, `dst [[0,1023]]` |
| 3040005 | `[10.0.0.1,172.16.0.0/12] any -> any [80,443,8000:8080]` | 2 net; `[[80,80],[443,443],[8000,8080]]` |
| 3040006 | `!10.0.0.0/8 any -> any !22` | `negate=true` ở src IP và dst port |
| 3040007 | `$HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS` | biến mở rộng: any / any / `[80,8000,8080,8888]` |
| 3040008 | `udp any any <> 8.8.8.8 53` | `protocol=udp`, `direction="<>"` |

Cả 8 rule `status=valid`.
