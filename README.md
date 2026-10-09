# Building an IDS using Python

Hệ thống IDS/IPS đơn giản: bắt packet (live interface hoặc file PCAP) → parse →
decode → chuẩn hóa → gán flow/connection → ghi JSON Lines. Output là input của
các module Feature Extractor / Detection Engine phía sau pipeline.

**Pipeline:**

```
Packet Capture & Parser
        ↓  event (JSON object)
Decoder → Preprocessor → Flow/Connection Tracker
        ↓
events.jsonl (mỗi packet 1 dòng)  +  flows.jsonl (mỗi flow đóng 1 dòng)
```

Mỗi mắt xích là một module riêng trong `src/`; `main.py` chỉ capture, gọi parse
và ghép các module lại với nhau.

### Tools and Libraries Used
- `Python`: for building the logic and handling the CLI.
- `Scapy`: to capture and parse network packets.
- `argparse`: to allow command-line arguments for interface selection and filtering.

### Project Structure
```
src/
  main.py               # CLI + capture + ghép pipeline (7 section/event)
  parse_network.py      # Network Parser: IPv4/IPv6
  parse_transport.py    # Transport Parser: TCP/UDP/ICMP
  parse_application.py  # Application Parser: HTTP/DNS/SMTP
  decoder.py            # percent/HTML entity/Base64/Quoted-Printable decoding
  preprocessor.py       # validation + normalization
  flow_tracker.py       # 5-tuple flow, TCP state, idle timeout, stats
TEST/                   # kết quả mỗi testcase (Bai-tap-01/, Bai-tap-02/): gen_input.py, input.pcap, output.jsonl, report.md
```

### Usage
```bash
python src/main.py --pcap test.pcap --count 10 --output out.jsonl
sudo python src/main.py --interface wlan0 --count 20
python src/main.py --pcap test.pcap --count 10 --output out.jsonl --pretty
```

| Flag | Ý nghĩa |
|---|---|
| `--pcap FILE` | đọc packet từ file PCAP (loại trừ `--interface`) |
| `--interface IF` | live capture từ interface (cần sudo) |
| `--count N` | số packet tối đa, mặc định 10 |
| `--output FILE` | file kết quả, mặc định `output.jsonl` |
| `--pretty` | JSON thụt lề 2 spaces, dễ đọc hơn |

### Output Format
Compact (mặc định, 1 packet = 1 dòng — dùng để máy đọc / jq):
```
{"packet_id":1,"timestamp":...,"network":{...},"transport":{...},"application":{...},"decoder":{...},"preprocess":{...},"flow":{...}}
```

Pretty (`--pretty`, 1 packet = nhiều dòng):
```
{
  "timestamp": ...,
  "network": { "protocol": "IPv4", "src_ip": ..., "dst_ip": ..., "ttl": ... },
  "transport": { "protocol": "TCP", "src_port": ..., "dst_port": ..., ... },
  "application": { "protocol": "HTTP", "type": "request", ... },
  "decoder": { "uri_decoded": ..., "decode_method": ..., "decode_status": ..., ... },
  "preprocess": { "preprocess_status": ..., "processing_action": ..., "reason": ..., "normalized": { ... } },
  "flow": { "flow_id": ..., "direction": ..., "state": ... },
  "packet_id": 1
}
```
File `--pretty` vẫn là JSON hợp lệ (nhiều document nối nhau): đọc bằng `jq -s '.' out.jsonl` hoặc `jq '.' out.jsonl`.

### Ý nghĩa 7 section của event

| Section | Module | Nội dung |
|---|---|---|
| `timestamp`, `packet_id` | `main.py` | thời điểm packet + thứ tự |
| `network` | `parse_network.py` | IPv4/IPv6: `src_ip`, `dst_ip`, `ttl`, `ip_length` (dùng tính `byte_count` của flow) |
| `transport` | `parse_transport.py` | TCP/UDP/ICMP: port, `flags` (TCP state), `payload_length`, `payload_b64` (bytes gốc để decode) |
| `application` | `parse_application.py` | HTTP/DNS/SMTP đã parse (path, body, DNS answers, SMTP command...) |
| `decoder` | `decoder.py` | kết quả decode: `uri_decoded`, `text_decoded`, `body_decoded`, `decode_method`, `decode_status` (`ok/partial/error/not_applicable`), `decode_reason` |
| `preprocess` | `preprocessor.py` | `preprocess_status` (`valid/partial/invalid`), `processing_action` (`continue/skip`), `reason`, `normalized` (protocol/IP/host/path/header/timestamp đã chuẩn hóa) |
| `flow` | `flow_tracker.py` | `flow_id`, `direction` (`forward/backward`), `state` (TCP: `HANDSHAKE → ESTABLISHED → CLOSING → CLOSED/RESET`) |

3 section cuối do `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py`
định nghĩa schema và điền giá trị; thiếu dữ liệu thì để `null` (field) hoặc `[]`
(list) cho nhất quán.

### Testcases

Mỗi testcase là 1 folder trong `TEST/Bai-tap-02/` — tái hiện được bằng 2 lệnh:

```bash
.venv/bin/python TEST/Bai-tap-02/T0x_<Tên>/gen_input.py   # sinh input.pcap
.venv/bin/python src/main.py --pcap TEST/Bai-tap-02/T0x_<Tên>/input.pcap \
    --count 20 --output TEST/Bai-tap-02/T0x_<Tên>/output.jsonl
```

Nội dung mỗi folder:
- `gen_input.py` – script sinh `input.pcap` (frame mô tả đúng case cần test)
- `input.pcap` – input tái tạo được, timestamp cố định
- `output.jsonl` – output thực tế của `main.py` trên input đó
- `report.md` – cách chạy, input là gì, bảng kết quả mong đợi

Quy tắc commit: 1 task = 1 commit, 1 testcase = 1 commit.

### AI Help

| Model | Mục đích | Phần mã dùng AI |
|---|---|---|
| `Big Pickle (OpenCode)` | Hỗ trợ xây dựng parser HTTP/DNS/SMTP | `src/parse_application.py`; `test.py` (script lọc packet phục vụ kiểm thử) |
| `9router/cl/cline-free/mimo-v2.6-flash:high` (omp coding assistant) | Thiết kế pipeline Decoder → Preprocessor → Flow Tracker, scaffold schema section | `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py`; phần ghép pipeline và field mới (`ip_length`, `payload_b64`, `smtp_body`) trong `src/main.py`, `src/parse_*.py` |
