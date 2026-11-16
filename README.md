# Python Signature-based IDS

Hệ thống phát hiện xâm nhập (IDS) dựa trên chữ ký: bắt packet từ card mạng hoặc
file PCAP, phân tích và giải mã nội dung, theo dõi từng kết nối, rồi so với bộ rule
cú pháp Snort để sinh cảnh báo. Mọi kết quả được ghi ra file JSON Lines để công cụ
khác (SIEM, script, `jq`) đọc tiếp.

## Architecture

![IDS Architecture](assets/architecture.png)


Hệ thống có hai luồng:

**Lúc khởi động (nét đứt):** rule được nạp **một lần**. Loader đọc file `.rules`,
Parser dịch từng rule sang dạng máy so được và loại rule viết sai, Repository xếp
rule hợp lệ theo protocol + port để tra nhanh.

**Với mỗi packet (nét liền, đánh số):**

| Step | Component | Responsibility |
|---|---|---|
| 1–2 | **Capture & Parse** | Scapy bắt packet; tách IP (L3), TCP/UDP/ICMP (L4), HTTP/DNS/SMTP (L7) thành một **event** dạng JSON |
| 3 | **Decoder** | Giải mã dữ liệu bị ngụy trang: URL `%27` (kể cả mã hóa nhiều lớp `%2527`), HTML entity, Base64, Quoted-Printable, form body |
| 4 | **Preprocessor** | Kiểm tra và chuẩn hóa event; event hỏng hoặc ngoài chính sách bị đánh dấu `skip` |
| 5 | **Flow Tracker** | Gom packet thành kết nối (5-tuple), biết chiều client→server và trạng thái TCP |
| 6–7 | **Evaluation Engine ⇄ Rule Repository** | Bỏ qua event `skip`; lấy các rule *liên quan* tới protocol/port của packet |
| 8–9 | **Matching Engine** | So từng rule theo thứ tự `header → flow → flags → dsize → content`, sai bước nào dừng ở bước đó |
| 10–11 | **Alert Generator** | Mỗi rule khớp sinh một alert, ghi vào `alerts.jsonl` |

Song song đó, mọi event được ghi vào `events.jsonl`, và mỗi kết nối được ghi vào
`flows.jsonl` ngay khi nó đóng (kết nối còn mở được ghi lúc chương trình kết thúc).

### Design Rationale

- **Decoder đứng trước Engine:** kẻ tấn công thường mã hóa payload. `%27%20OR%201%3D1`
  chỉ khớp rule `content:"' OR 1=1"` sau khi được giải mã. Matcher tìm content
  trong payload gốc **và** trong dữ liệu đã giải mã.
- **Flow Tracker đứng trước Engine:** rule như `flow:to_server,established` cần biết
  packet đi chiều nào và kết nối đã bắt tay xong chưa — một packet đơn lẻ không cho
  biết điều đó.
- **Rule được biên dịch sẵn lúc khởi động:** dịch biến (`$HTTP_PORTS`), hex
  (`|0d 0a|`), dải IP chỉ làm một lần; rule sai bị báo ngay thay vì làm hỏng lúc chạy.
- **Index theo protocol + port:** packet DNS port 53 không phải thử rule HTTP port 80.
- **Matcher kiểm tra từ rẻ đến đắt:** so IP/port trước, tìm chuỗi trong payload sau
  cùng, nên đa số rule bị loại trước khi phải tìm chuỗi.
- **Không có module nào làm dừng hệ thống:** packet hỏng, rule sai, file rule thiếu
  đều chỉ sinh cảnh báo.
- **Chạy lâu không phình bộ nhớ:** flow đã đóng được ghi ra file ngay rồi bỏ khỏi
  RAM; việc tìm content ghi nhớ các lần thử thất bại nên payload do kẻ tấn công dựng
  không làm engine đứng.

## Components

| Component | File | Notes |
|---|---|---|
| CLI, capture, ghép pipeline | `src/main.py` | Gọi lần lượt các module, ghi file đầu ra |
| Parser L3 / L4 / L7 | `src/parse_network.py`, `parse_transport.py`, `parse_application.py` | IPv4/IPv6; TCP/UDP/ICMP; HTTP/DNS/SMTP |
| Decoder | `src/decoder.py` | `uri_decoded`, `text_decoded`, `body_decoded` + trạng thái decode |
| Preprocessor | `src/preprocessor.py` | `valid/partial/invalid`, `continue/skip`, dữ liệu đã chuẩn hóa |
| Flow Tracker | `src/flow_tracker.py` | 5-tuple, trạng thái TCP, idle timeout, thống kê flow |
| Rule Loader | `src/rule_loader.py` | Đọc nhiều file `.rules`, bỏ comment, nối dòng `\`, bật/tắt theo config |
| Rule Parser | `src/rule_parser.py` | Rule text → Rule Object; phân loại `valid / invalid / unsupported` |
| Rule Repository | `src/rule_repository.py` | Lưu rule hợp lệ, index theo protocol + port |
| Evaluation Engine | `src/engine.py` | Lấy rule ứng viên, gọi matcher, thống kê |
| Matching Engine | `src/rule_matcher.py` | `MATCH / NO_MATCH` + bước bị loại + lý do |
| Alert Generator | `src/detection.py` | Alert theo schema cố định |

## Getting Started

Yêu cầu Python 3 và Scapy.

```bash
python3 -m venv .venv
.venv/bin/pip install scapy
```

Cách dùng giống Snort/Suricata: chọn nguồn packet, trỏ tới file cấu hình, kết quả
ghi vào một thư mục log.

```bash
# đọc file PCAP
.venv/bin/python src/main.py -r capture.pcap -c rules/engine.json

# giám sát trực tiếp trên card mạng (cần root, dừng bằng Ctrl+C)
sudo .venv/bin/python src/main.py -i eth0 -c rules/engine.json -l /var/log/ids

# chỉ kiểm tra bộ rule rồi thoát
.venv/bin/python src/main.py -T -c rules/engine.json
```

| Option | Description |
|---|---|
| `-r PCAP` / `-i IFACE` | Đọc file PCAP hoặc bắt trực tiếp trên card mạng |
| `-c CONFIG` | File cấu hình: rule, biến, timeout, chính sách (xem mục Configuration) |
| `-s RULES` | Nạp thêm file `.rules`, lặp lại được |
| `-l DIR` | Thư mục log, mặc định `logs/` |
| `-n N` | Dừng sau N packet, mặc định không giới hạn |
| `-T` | Chỉ nạp và kiểm tra rule rồi thoát |
| `-v` | Ghi thêm `trace.jsonl` và `rules_report.jsonl` để gỡ lỗi |

Cảnh báo khi nạp rule và thống kê engine được in ra stderr.

## Output

Mọi file nằm trong thư mục log (`-l`):

| File | One line per |
|---|---|
| `events.jsonl` | Một packet đã xử lý (event) |
| `alerts.jsonl` | Một lần rule khớp (khi có rule) |
| `flows.jsonl` | Một kết nối, ghi ngay khi kết nối đóng, kèm số packet/byte và lý do kết thúc |
| `trace.jsonl` | (`-v`) Rule ứng viên và kết quả MATCH/NO_MATCH của từng event |
| `rules_report.jsonl` | (`-v`) Trạng thái và lý do của từng rule |

**Event** gồm 7 phần, mỗi phần do một module điền:

| Section | Module | Content |
|---|---|---|
| `packet_id`, `timestamp` | `main.py` | Thứ tự và thời điểm packet |
| `network` | parser L3 | `src_ip`, `dst_ip`, `ttl`, `ip_length` |
| `transport` | parser L4 | Port, cờ TCP, `payload_length`, `payload_b64` |
| `application` | parser L7 | HTTP method/path/header/body, DNS query/answer, lệnh SMTP |
| `decoder` | Decoder | Dữ liệu đã giải mã, `decode_method`, `decode_status` |
| `preprocess` | Preprocessor | `preprocess_status`, `processing_action`, `reason`, `normalized` |
| `flow` | Flow Tracker | `flow_id`, `direction`, `state` |

Thiếu dữ liệu thì field là `null`, list là `[]`.

**Alert** ví dụ:

```json
{"timestamp": 1700000003.0, "packet_id": 4, "sid": 100001, "rev": 1,
 "msg": "Directory traversal detected", "priority": 1, "classtype": "web-application-attack",
 "protocol": "TCP", "application_protocol": "HTTP",
 "src_ip": "10.0.0.5", "src_port": 52133, "dst_ip": "192.168.1.20", "dst_port": 80,
 "flow_id": "flow-0001", "flow_direction": "forward", "flow_state": "ESTABLISHED",
 "match": {"contents": [{"content": "../", "buffer": "payload", "offset": 12, "nocase": false}],
           "flow": {"direction": "to_server", "state": "established"}}}
```

`match` cho biết rule khớp ở đâu: content nào, trong vùng dữ liệu nào (`payload`
hay `uri_decoded`...), ở vị trí nào.

## Writing Rules

Rule dùng cú pháp Snort, mỗi rule một dòng (hoặc nối dòng bằng `\`):

```
alert tcp any any -> any $HTTP_PORTS (msg:"SQL injection OR 1=1"; flow:to_server,established; content:"' OR 1=1"; nocase; sid:1000002; rev:1;)
```

| Part | Supported |
|---|---|
| Action | `alert` |
| Protocol | `tcp`, `udp`, `ip` |
| IP | `any`, IPv4, CIDR, `[list]`, `!`, biến `$HOME_NET`... |
| Port | `any`, `80`, `1:1024`, `[80,443]`, `!`, biến `$HTTP_PORTS`... |
| Chiều | `->`, `<>` |
| Thông tin | `msg`, `sid` (bắt buộc), `rev`, `classtype`, `priority`; `reference`/`metadata` được bỏ qua |
| Điều kiện | `content` (cả `\|hex\|`) với `nocase`, `offset`, `depth`, `distance`, `within`; `flags`; `dsize`; `flow` (`to_server`, `to_client`, `established`, `not_established`) |

Rule dùng tính năng chưa hỗ trợ (`pcre`, `byte_test`, `icmp`, action `drop`...) được
đánh dấu `unsupported` và bỏ qua; rule sai cú pháp bị đánh dấu `invalid`. Cả hai chỉ
sinh cảnh báo, không làm dừng hệ thống.

## Configuration

Mọi thiết lập nằm trong một file JSON truyền bằng `-c` (bản mặc định: `rules/engine.json`).
Không có `-c` thì IDS chạy không rule, với timeout và chính sách mặc định như bên dưới.
Đổi hành vi IDS bằng cách sửa file này, không cần sửa code hay thêm tham số dòng lệnh.

```json
{
  "rule_files": [{"path": "local.rules", "enabled": true}],
  "disabled_sids": [],
  "variables": {"HOME_NET": "any", "EXTERNAL_NET": "any", "HTTP_PORTS": "[80,8000,8080,8888]"},
  "flow_timeout": {"tcp": 300, "udp": 60},
  "skip_unknown": false,
  "max_payload": null
}
```

| Key | Description |
|---|---|
| `rule_files` | File rule cần nạp (đường dẫn tính từ thư mục chứa file cấu hình), bật/tắt từng file |
| `disabled_sids` | Tắt từng rule theo `sid` |
| `variables` | Giá trị các biến dùng trong rule (`$HOME_NET`, `$HTTP_PORTS`...) |
| `flow_timeout` | Số giây không có packet trước khi đóng flow TCP / UDP |
| `skip_unknown` | `true`: không đánh giá event có protocol ứng dụng `UNKNOWN` |
| `max_payload` | Không đánh giá payload lớn hơn N byte (`null` = không giới hạn) |

Khóa bỏ trống thì dùng giá trị mặc định ở trên. Khóa sai tên hoặc sai kiểu (ví dụ
`"max_payload": "200"`) bị báo lỗi ngay khi khởi động, IDS không chạy với cấu hình sai.

Bộ rule mẫu `rules/local.rules` phát hiện: directory traversal, SQL injection, XSS,
truy cập `/etc/passwd`, quét SYN/NULL/XMAS, truy vấn DNS tên miền `.xyz`, lệnh SMTP `EXPN`.

## Project Structure

```
src/        mã nguồn (bảng Components ở trên)
rules/      local.rules (bộ rule mẫu), engine.json (cấu hình mặc định)
assets/     sơ đồ kiến trúc (.png + .excalidraw)
TEST/       testcase: input.pcap tái tạo được + kết quả thực tế + report.md
docs/       tài liệu tham khảo cho các hướng phát triển
test.py     công cụ trích packet theo protocol từ một PCAP lớn để làm testcase
```

`test.py` cần file `ultimate_wireshark_protocols_pcap_220213.pcap` (87 MB) ở thư mục
gốc. File này không nằm trong git; tải riêng và đặt vào đó.

## Testing

Mỗi testcase là một thư mục có `gen_input.py` (sinh `input.pcap` với timestamp cố
định), kết quả thực tế (`events.jsonl`, `flows.jsonl`, `alerts.jsonl`, `trace.jsonl`...)
và `report.md` (lệnh chạy, input, kết quả mong đợi).

| Directory | Covers |
|---|---|
| `TEST/Bai-tap-01/` | Capture & Parse: TCP handshake, HTTP, DNS, SMTP, protocol lạ, packet hỏng |
| `TEST/Bai-tap-02/T01–T06, T14, T16, T17` | Decoder và Preprocessor: URL/HTML/MIME decode, chuẩn hóa, event hỏng, chính sách skip |
| `TEST/Bai-tap-02/T07–T13, T15` | Flow Tracker: handshake, hai chiều, đóng kết nối, UDP, nhiều flow, timeout, thống kê |
| `TEST/Bai-tap-03/T01–T06` | Nạp rule: loader, rule sai, keyword chưa hỗ trợ, header, chiều, index |
| `TEST/Bai-tap-03/T07–T14` | So khớp: header, flow, content/nocase, offset/depth, distance/within, flags/dsize, nhiều rule, alert |

Chạy lại một testcase:

```bash
.venv/bin/python TEST/Bai-tap-02/T01_HTTP_URL_Decode/gen_input.py
.venv/bin/python src/main.py -r TEST/Bai-tap-02/T01_HTTP_URL_Decode/input.pcap \
    -n 20 -l TEST/Bai-tap-02/T01_HTTP_URL_Decode
```

Lệnh cụ thể của từng testcase nằm trong `report.md` của thư mục đó.

## Roadmap

Các hướng mở rộng tiếp theo (tham khảo thêm `docs/`):

- Alert/Logging/Response: đọc `alerts.jsonl` để gửi thông báo hoặc chặn kết nối (IPS).
- Mở rộng rule: `pcre`, `http_uri`, `byte_test`, ICMP, IPv6.
- Tái hợp TCP stream để phát hiện tấn công trải trên nhiều packet.

Quy tắc commit: 1 task = 1 commit, 1 testcase = 1 commit.

## AI Usage

| Model | Hỗ trợ |
|---|---|
| Big Pickle (OpenCode) | Parser HTTP/DNS/SMTP (`parse_application.py`), `test.py` |
| mimo-v2.6-flash (omp) | Decoder, Preprocessor, Flow Tracker và phần ghép pipeline |
| Claude Opus 5.5 (Claude Code) | Detection engine (`rule_*.py`, `engine.py`, `detection.py`), testcase engine, sửa lỗi và audit, cấu trúc `main.py` + CLI, sơ đồ kiến trúc, README |
