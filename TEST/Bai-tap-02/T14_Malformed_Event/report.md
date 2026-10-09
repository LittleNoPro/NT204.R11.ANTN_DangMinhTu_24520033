# T14 — Malformed event

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T14_Malformed_Event/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T14_Malformed_Event/input.pcap \
    --count 20 \
    --output TEST/Bai-tap-02/T14_Malformed_Event/output.jsonl
```

Kiểm tra nhánh event hỏng mức event (port/timestamp/IP sai — không tạo được
từ pcap vì scapy luôn pack trong khoảng hợp lệ):

```bash
cd src && python -c "
import preprocessor, decoder, flow_tracker
e = {'timestamp': 'not-a-number',
     'network': {'protocol': 'IPv4', 'src_ip': '999.1.1.1', 'dst_ip': None},
     'transport': {'protocol': 'WAT', 'src_port': 99999, 'dst_port': -1},
     'application': {'protocol': None},
     'decoder': decoder.new_section(), 'preprocess': preprocessor.new_section(),
     'flow': flow_tracker.new_section()}
p = preprocessor.apply(e)['preprocess']
print(p['preprocess_status'], p['processing_action'], p['reason'])"
```

## Input

- `input.pcap` — 6 frame malformed: TCP header cắt cụt 10 byte, IP version 15,
  Ethernet type IPv4 nhưng payload không phải IP, `ip.len=1000` nhưng capture 60
  byte, UDP `len=0`, TCP `sport=0`.

## Output

- `output.jsonl` — 6 event, quan tâm `preprocess_status` / `reason` /
  `transport.parse_error`.

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | TCP header cắt cụt | `partial`, transport `UNKNOWN` (scapy không dissect nổi), không crash |
| 2 | IP version sai (0xF) | `partial`, `protocol = UNKNOWN`, không crash |
| 3 | Ethernet type IPv4, payload rác | `partial`, `UNKNOWN` + reason |
| 4 | `ip.len` nói dối (1000 vs 60) | `partial`, parse ra UNKNOWN, không crash |
| 5 | UDP `len=0` | `valid` — UDP vẫn parse được, payload giữ nguyên |
| 6 | TCP `sport=0`, payload rác | `partial` (trong range nhưng application unknown) |
| — | Event hỏng trực tiếp (port 99999, timestamp string, IP `999.1.1.1`, protocol `WAT`) | `invalid` + `skip` + reason liệt kê đủ 5 lỗi, normalized fallback `null` |

Toàn bộ: exit 0 — packet/event hỏng không làm dừng chương trình; trạng thái
`partial`/`invalid` và `reason` trỏ đúng lỗi, `processing_action` quyết định
skip/continue theo cấu hình (mặc định: invalid → skip).
