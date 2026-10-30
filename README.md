# Building an IDS using Python

Hệ thống IDS/IPS đơn giản: bắt packet (live interface hoặc file PCAP) → parse →
decode → chuẩn hóa → gán flow/connection → ghi JSON Lines. Output là input của
các module Feature Extractor / Detection Engine phía sau pipeline.

**Pipeline:**

```
Packet Capture & Parser
        ↓  event (JSON object)
Decoder → Preprocessor → Flow/Connection Tracker
        ↓  normalized event + flow context
Core Engine: Evaluation Engine → Repository/Indexer → Matching Engine → Detection Event
        ↓
events.jsonl (mỗi packet 1 dòng) + flows.jsonl (mỗi flow đóng 1 dòng) + alerts.jsonl (mỗi rule match 1 dòng)
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
  flow_tracker.py       # 5-tuple flow, TCP state, idle timeout, stats, flow context
  rule_loader.py        # BT3: đọc file .rules + config enable/disable
  rule_parser.py        # BT3: Rule Parser & Validator → Internal Rule Object
  rule_repository.py    # BT3: Rule Repository / Indexer (protocol + port)
  rule_matcher.py       # BT3: Rule Matching Engine (header/flow/flags/dsize/content)
  engine.py             # BT3: Rule Evaluation Engine + thống kê
  detection.py          # BT3: Detection Event Generator
rules/
  local.rules           # bộ rule mẫu (cú pháp Snort)
  engine.json           # cấu hình: rule_files (enabled), disabled_sids, variables
TEST/                   # kết quả mỗi testcase (Bai-tap-01/, Bai-tap-02/, BT3/): gen_input.py, input.pcap, output.jsonl, report.md
```

### Usage
```bash
python src/main.py --pcap test.pcap --count 10 --output out.jsonl
sudo python src/main.py --interface wlan0 --count 20
python src/main.py --pcap test.pcap --count 10 --output out.jsonl --pretty
python src/main.py --pcap test.pcap --output out.jsonl --flows flows.jsonl
python src/main.py --pcap test.pcap --count 100 --rules-config rules/engine.json --alerts alerts.jsonl
python src/main.py --check-rules --rules rules/local.rules --rules-report rules_report.jsonl
```

| Flag | Ý nghĩa |
|---|---|
| `--pcap FILE` | đọc packet từ file PCAP (loại trừ `--interface`) |
| `--interface IF` | live capture từ interface (cần sudo) |
| `--count N` | số packet tối đa, mặc định 10 |
| `--output FILE` | file kết quả, mặc định `output.jsonl` |
| `--pretty` | JSON thụt lề 2 spaces, dễ đọc hơn |
| `--flows FILE` | ghi flow đã đóng vào file jsonl (vd `flows.jsonl`) |
| `--tcp-timeout N` | idle timeout TCP (giây), mặc định 300 |
| `--udp-timeout N` | idle timeout UDP (giây), mặc định 60 |
| `--rules FILE` | file `.rules` (lặp lại được để nạp nhiều file) |
| `--rules-config FILE` | cấu hình JSON: `rule_files` (bật/tắt từng file), `disabled_sids`, `variables` |
| `--alerts FILE` | ghi Detection Event, mặc định `alerts.jsonl` (chỉ khi có rule) |
| `--rules-report FILE` | ghi Internal Rule Object + `status`/`reason` của mọi rule |
| `--trace FILE` | ghi candidate rules và kết quả MATCH/NO_MATCH của từng event |
| `--stats FILE` | ghi thống kê engine (JSON) |
| `--check-rules` | chỉ nạp/validate rule rồi thoát (không cần `--pcap`) |

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

### Core Engine (Bài tập 3)

Engine chỉ làm việc với event đã chuẩn hóa + flow context, không đọc packet Scapy.

| Module | Nhiệm vụ |
|---|---|
| `rule_loader.py` | đọc nhiều file `.rules`, bỏ comment/dòng trống, nối rule nhiều dòng (`\`), bật/tắt file hoặc sid theo config; file lỗi chỉ cảnh báo |
| `rule_parser.py` | tách header/options → Internal Rule Object; phân loại `valid` / `invalid` / `unsupported` kèm `reason` |
| `rule_repository.py` | lưu rule valid, index theo protocol + port (dst/src/`<>`/generic) để lấy candidate |
| `rule_matcher.py` | kiểm tra theo thứ tự header → flow → flags → dsize → content, trả `MATCH`/`NO_MATCH` + `stage` |
| `engine.py` | lấy candidate, gọi matcher cho từng rule (nhiều rule cùng match được), thống kê |
| `detection.py` | sinh Detection Event: timestamp, sid/rev/msg, priority/classtype, 5-tuple, protocol, application_protocol, flow_id, match info |

Phạm vi rule hỗ trợ: action `alert`; protocol `tcp`/`udp`/`ip`; IP any/IPv4/CIDR/list/`!`;
port any/single/range/list/`!`; biến `$HOME_NET`, `$HTTP_PORTS`...; direction `->`, `<>`;
`msg`, `sid`, `rev`, `classtype`, `priority`; `content` (+ `|hex|`), `nocase`, `offset`,
`depth`, `distance`, `within`; `flags`; `dsize`; `flow` (`to_server`, `to_client`,
`established`, `not_established`). `reference`/`metadata` được chấp nhận và bỏ qua.
Keyword khác (`pcre`, `http_uri`, `byte_test`...), action khác `alert`, protocol `icmp`
→ `unsupported`, không làm dừng chương trình.

Content được tìm trong payload gốc trước, sau đó trong dữ liệu Decoder đã giải mã
(`uri_decoded`, `text_decoded`, `body_decoded`) — ví dụ `%27%20OR%201%3D1` vẫn khớp
`content:"' OR 1=1"`. `to_server` = chiều forward của flow (phía khởi tạo kết nối);
`established` = TCP `ESTABLISHED`/`CLOSING`, UDP khi đã thấy cả hai chiều.

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
- `flows.jsonl` – flow record đã đóng (testcase flow T07–T13, chạy với `--flows`)
- `report.md` – cách chạy, input là gì, bảng kết quả mong đợi

Testcase Bài tập 3 nằm trong `TEST/BT3/T01..T14`, cùng format; thêm `test.rules`
(rule của testcase), `rules_report.jsonl`, `alerts.jsonl`, `trace.jsonl`, `engine.log`.
Lệnh chạy nằm trong `report.md` của từng folder.

Quy tắc commit: 1 task = 1 commit, 1 testcase = 1 commit.

### AI Help

| Model | Mục đích | Phần mã dùng AI |
|---|---|---|
| `Big Pickle (OpenCode)` | Hỗ trợ xây dựng parser HTTP/DNS/SMTP | `src/parse_application.py`; `test.py` (script lọc packet phục vụ kiểm thử) |
| `9router/cl/cline-free/mimo-v2.6-flash:high` (omp coding assistant) | Thiết kế pipeline Decoder → Preprocessor → Flow Tracker, scaffold schema section | `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py`; phần ghép pipeline và field mới (`ip_length`, `payload_b64`, `smtp_body`) trong `src/main.py`, `src/parse_*.py` |
| `Claude Opus 5.5 (Claude Code)` | Bài tập 3: thiết kế và viết Core Engine, testcase BT3; sửa lỗi mất payload HTTP/DNS ở transport parser | `src/rule_loader.py`, `src/rule_parser.py`, `src/rule_repository.py`, `src/rule_matcher.py`, `src/engine.py`, `src/detection.py`, `context()` trong `src/flow_tracker.py`, phần CLI rule trong `src/main.py`, `_payload_bytes` trong `src/parse_transport.py`, `rules/`, `TEST/BT3/` |
