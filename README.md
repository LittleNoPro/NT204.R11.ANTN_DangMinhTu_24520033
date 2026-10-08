# Building an IDS using Python

Hệ thống IDS/IPS đơn giản: bắt packet (live interface hoặc file PCAP) → parse →
decode → chuẩn hóa → gán flow/connection → ghi JSON Lines. Output là input của
các module Feature Extractor / Detection Engine ở bài tập sau.

**Pipeline:**

```
Packet Capture & Parser (Bài tập 1)
        ↓  event (JSON object)
Decoder → Preprocessor → Flow/Connection Tracker (Bài tập 2)
        ↓
events.jsonl (mỗi packet 1 dòng)  +  flows.jsonl (mỗi flow đóng 1 dòng)
```

Mỗi mắt xích là một module riêng trong `src/`; `main.py` chỉ capture, gọi parse
và ghép các module lại với nhau. Chi tiết làm từng bước: [`GUIDE.md`](GUIDE.md).

### Tools and Libraries Used
- `Python`: for building the logic and handling the CLI.
- `Scapy`: to capture and parse network packets.
- `argparse`: to allow command-line arguments for interface selection and filtering.

### Project Structure
```
src/
  main.py               # CLI + capture + ghép pipeline (7 section/event)
  parse_network.py      # BT01 – Network Parser: IPv4/IPv6
  parse_transport.py    # BT01 – Transport Parser: TCP/UDP/ICMP
  parse_application.py  # BT01 – Application Parser: HTTP/DNS/SMTP
  decoder.py            # BT02 §3 – percent/HTML entity/Base64/Quoted-Printable
  preprocessor.py       # BT02 §4 – validation + normalization
  flow_tracker.py       # BT02 §5 – 5-tuple flow, TCP state, idle timeout, stats
tests/                  # pytest – 1 file/testcase (T01–T14)
TEST/                   # kết quả mỗi testcase: input.pcap, output.jsonl, report.md
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

| Section | Nguồn | Nội dung |
|---|---|---|
| `timestamp`, `packet_id` | BT01 | thời điểm packet + thứ tự |
| `network` | BT01 | IPv4/IPv6: `src_ip`, `dst_ip`, `ttl`, `ip_length` (dùng tính `byte_count` của flow) |
| `transport` | BT01 | TCP/UDP/ICMP: port, `flags` (TCP state), `payload_length`, `payload_b64` (bytes gốc để decode) |
| `application` | BT01 | HTTP/DNS/SMTP đã parse (path, body, DNS answers, SMTP command...) |
| `decoder` | BT02 | kết quả decode: `uri_decoded`, `text_decoded`, `body_decoded`, `decode_method`, `decode_status` (`ok/partial/error/not_applicable`), `decode_reason` |
| `preprocess` | BT02 | `preprocess_status` (`valid/partial/invalid`), `processing_action` (`continue/skip`), `reason`, `normalized` (protocol/IP/host/path/header/timestamp đã chuẩn hóa) |
| `flow` | BT02 | `flow_id`, `direction` (`forward/backward`), `state` (TCP: `HANDSHAKE → ESTABLISHED → CLOSING → CLOSED/RESET`) |

3 section cuối do `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py`
định nghĩa schema và điền giá trị; thiếu dữ liệu thì để `null` (field) hoặc `[]`
(list) cho nhất quán.

### Tests
```bash
.venv/bin/python -m pytest tests/ -q                              # toàn bộ
.venv/bin/python -m pytest tests/test_t01_url_decode.py -q        # 1 testcase
```
Mỗi testcase để lại kết quả trong `TEST/T0x_<Tên>/`:
- `input.pcap` – input tái tạo được (test tự sinh, timestamp cố định)
- `output.jsonl` – output thực tế khi chạy `main.py` trên input đó
- `report.md` – cách chạy, input là gì, output là gì, bảng assert
- `flows.jsonl` – riêng testcase flow (T07–T13)

Quy tắc commit: 1 task = 1 commit, 1 testcase = 1 commit (xem `GUIDE.md`).

### AI Help

| Model | Mục đích | Phần mã dùng AI |
|---|---|---|
| `Big Pickle (OpenCode)` | Hỗ trợ Bài tập 1 | `src/parse_application.py`; `test.py` (script lọc packet phục vụ kiểm thử) |
| `9router/cl/cline-free/mimo-v2.6-flash:high` (omp coding assistant) | Thiết kế pipeline Bài tập 2 (Decoder → Preprocessor → Flow Tracker), scaffold schema, viết `GUIDE.md` | `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py`; phần ghép pipeline và field mới (`ip_length`, `payload_b64`, `smtp_body`) trong `src/main.py`, `src/parse_*.py`; `GUIDE.md` |
