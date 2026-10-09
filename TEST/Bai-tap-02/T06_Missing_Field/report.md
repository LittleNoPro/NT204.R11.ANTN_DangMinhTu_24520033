# T06 — Missing field

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T06_Missing_Field/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T06_Missing_Field/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T06_Missing_Field/output.jsonl
```

## Input

- `input.pcap` — 5 frame không có / thiếu field không bắt buộc:
  ARP (không IP/port), ICMP (không port), TCP SYN rỗng (không payload),
  UDP rỗng, Ethernet unknown ethertype.

## Output

- `output.jsonl` — 5 event, quan tâm `preprocess` + section khác còn `null`.

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | ARP — không IP, không port | `partial` + `continue`, `protocol = UNKNOWN`, IP/port `null`, `header_names = []` |
| 2 | ICMP — không port | `partial`, `protocol = ICMP`, ports `null`, `header_names = []` |
| 3 | TCP SYN rỗng — không application | `partial` + reason `application protocol unknown`, mọi field application `null` |
| 4 | UDP rỗng, port không phổ biến | `partial`, các field thiếu = `null`/`[]` |
| 5 | Ethernet unknown ethertype 0x88B5 | `partial`, `protocol = UNKNOWN`, không crash |

Toàn bộ: 5/5 event exit 0, không exception — mọi field thiếu nhận giá trị
`null` (field) hoặc `[]` (list), `normalized.timestamp` vẫn là float,
`processing_action = continue` (đánh dấu chứ không bỏ qua theo mặc định).
