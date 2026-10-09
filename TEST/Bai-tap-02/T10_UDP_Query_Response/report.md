# T10 — UDP query/response (DNS)

## Cách chạy

```bash
.venv/bin/python TEST/Bai-tap-02/T10_UDP_Query_Response/gen_input.py
.venv/bin/python src/main.py \
    --pcap TEST/Bai-tap-02/T10_UDP_Query_Response/input.pcap \
    --count 50 --output TEST/Bai-tap-02/T10_UDP_Query_Response/output.jsonl \
    --flows TEST/Bai-tap-02/T10_UDP_Query_Response/flows.jsonl
```

## Input

- `input.pcap` — 2 frame DNS `192.168.1.10:51000 ↔ 8.8.8.8:53`:
  query (id=0x1234, example.com) + response (A record 93.184.216.34).

## Output

- `output.jsonl` (2 event) + `flows.jsonl` (1 flow).

## Kết quả

| Frame | Nội dung | Kết quả |
|---|---|---|
| 1 | DNS query client→server | `flow-0001`, `direction=forward`, `state=NEW` (UDP không có trạng thái kết nối) |
| 2 | DNS response server→client | cùng `flow_id`, `direction=backward` |
| — | flow record | **1 UDP flow**: `protocol=UDP`, `application_protocol=DNS`, `packet_count=2`, `forward=1/`, `backward=1`, `byte_count` = tổng `ip_length` 2 packet |
