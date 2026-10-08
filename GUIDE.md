# GUIDE — Bài tập 2: Decoder, Preprocessor & Flow/Connection Tracker

Quy tắc commit: **1 task = 1 commit, 1 testcase = 1 commit**.
Mỗi testcase để lại đủ artefact trong `TEST/T0x_<Tên>/`.

---

## 1. Pipeline & trạng thái hiện tại

```
PCAP/live → [BT01 parse] → event → [Decoder] → [Preprocessor] → [FlowTracker] → events.jsonl
                                                                          └→ flows.jsonl
```

Repo đã có (BT01 hoàn chỉnh + scaffold BT02):

- `src/main.py` — aggregator: capture → parse → ghép 3 section → ghi JSONL. Chỗ nối stage nằm trong `process_packet` (3 dòng comment chờ `decoder.apply` / `preprocessor.apply` / `tracker.track`).
- `src/decoder.py`, `src/preprocessor.py`, `src/flow_tracker.py` — mỗi module có schema section của mình + `new_section()`, **chưa có logic apply**.
- Raw fields đã có sẵn cho BT02: `network.ip_length` (byte_count), `transport.payload_b64` (bytes gốc), `application.smtp_body` (MIME đa dòng).
- Đã bỏ: `transport.payload` (lossy), `decoder.uri_raw` (trùng `application.path`).

Field 3 section:

| Section | Fields |
|---|---|
| `decoder` | `uri_decoded, text_decoded, body_decoded, decode_method, decode_status, decode_reason` |
| `preprocess` | `preprocess_status, processing_action, reason, normalized{protocol,src_ip,dst_ip,host,path,header_names,timestamp}` |
| `flow` | `flow_id, direction, state` |

---

## 2. Quy trình lặp cho MỌI task/testcase

```
1. Code xong        → 2. chạy test PASS → 3. ghi artefact vào TEST/T0x_<Tên>/
→ 4. git add đúng file  → 5. commit NGAY
```

Chạy lẻ 1 test:

```bash
.venv/bin/python -m pytest tests/test_t0x_<tên>.py -q
```

Trước khi commit testcase mới: chạy lại toàn bộ test cũ (regression) — stage trước không được phá stage sau.

**Không bao giờ `git add .`** — chỉ add file task hiện tại. Scratch chưa track: `output.jsonl`, `extracted.pcap`, `.verify/`.

---

## 3. Cấu trúc bắt buộc của 1 folder testcase

```
TEST/T0x_<Tên>/
├── input.pcap      # input tái tạo được (script test tự sinh, timestamp cố định)
├── output.jsonl    # output thực tế khi chạy main.py trên input.pcap
├── flows.jsonl     # CHỈ testcase flow (T07–T13)
├── report.md       # báo cáo thầy yêu cầu: cách chạy, input, output (mẫu ở §4)
└── result.txt      # dòng PASS/FAIL của test (optional nhưng nên có)
```

Lưu ý:

- **Tất cả T01–T14 đều phải có `input.pcap` + `output.jsonl`** kể cả unit test thuần event — khi đó test vẫn chạy E2E trên pcap để sinh 2 file này, assert phần event-level bằng cách gọi trực tiếp `apply()`.
- Test tự sinh `input.pcap` mỗi lần chạy (deterministic: set `pkt.time` tường minh, không dùng `time.time()`).
- Test tự chạy CLI để sinh `output.jsonl` (không commit output tay viết).

Mẫu helper ở `tests/helpers.py`:

```python
from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter

def write_pcap(path, packets):
    w = PcapWriter(path, sync=True)
    for p in packets:
        w.write(p)
    w.close()

def run_cli(pcap, out, flows=None, extra=()):
    """Chạy src/main.py --pcap, trả về list event dict."""
    import subprocess, json, sys
    cmd = [sys.executable, "src/main.py", "--pcap", pcap,
           "--count", "100", "--output", out, *extra]
    if flows:
        cmd += ["--flows", flows]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    return [json.loads(l) for l in open(out)]

def make_event(**overrides):
    """Event mẫu đủ 3 section; overrides theo tầng."""
    from decoder import new_section as nd
    from preprocessor import new_section as np_
    from flow_tracker import new_section as nf
    event = {
        "timestamp": 1700000000.0,
        "network": {"protocol": "IPv4", "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2", "ttl": 64, "hop_limit": None,
                    "ip_length": 100},
        "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80,
                      "flags": "PA", "seq": 1, "ack": 1, "length": None,
                      "type": None, "code": None, "payload_length": 10,
                      "payload_b64": None},
        "application": {"protocol": None, "type": None},
        "decoder": nd(), "preprocess": np_(), "flow": nf(),
        "packet_id": 1,
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(event.get(k), dict):
            event[k].update(v)
        else:
            event[k] = v
    return event
```

---

## 4. Mẫu `report.md` cho mỗi folder testcase

```markdown
# T0x — <Tên testcase>

## Cách chạy
```bash
.venv/bin/python src/main.py --pcap TEST/T0x_<Tên>/input.pcap \
    --count 100 --output TEST/T0x_<Tên>/output.jsonl
# (flow testcase thêm:) --flows TEST/T0x_<Tên>/flows.jsonl --udp-timeout 5
.venv/bin/python -m pytest tests/test_t0x_<tên>.py -q
```

## Input
- `input.pcap`: N packet — mô tả 5-tuple, flags/payload, timestamp relevant.
- Sinh bởi `tests/test_t0x_<tên>.py` (tái tạo được, timestamp cố định).

## Output
- `output.jsonl`: N event. Trường quan trọng:
  - `decoder.uri_decoded = "..."`, `decode_status = "ok"`
- (flow: `flows.jsonl` — 1 record: flow_id, state, end_reason, counters.)

## Kết quả
| Assert | Giá trị | PASS |
|---|---|---|
| uri_decoded | `/search?q=' OR 1=1` | ✓ |
| application.path giữ nguyên | `%27%20...` | ✓ |
```

---

## 5. Phase 0 — Chuẩn bị (2 commit)

1. Thêm vào `.gitignore`: `output.jsonl`, `extracted.pcap`, `.verify/`
   → `git add .gitignore && git commit -m "update gitignore"`
2. Commit đề bài:
   → `git add docs/Bai-tap-02_Decoder_Preprocessor_Flow_Tracker_IDS.pdf && git commit -m "add bai-tap-02 spec"`
3. Test framework: `.venv/bin/pip install pytest` (offline → dùng `unittest` stdlib, chỉnh lại tên lệnh trong GUIDE này).
4. Commit GUIDE.md này: `git add GUIDE.md && git commit -m "add testcase guide"`

---

## 6. Phase 1 — DECODER (1 task + T01–T04)

### Task: `decoder.apply(event) -> event`

Hàm thuần, đọc event dict (không nhận scapy packet), **không bao giờ raise**:

```python
def apply(event):
    section = event["decoder"]
    app = event.get("application") or {}
    transport = event.get("transport") or {}

    try:
        # T01: percent decode — GIỮ application.path nguyên
        path = app.get("path")
        if path and "%" in path:
            section["uri_decoded"] = unquote(path)   # urllib.parse
            section["decode_method"] = "percent"

        # T02: HTML entity trên text body HTTP
        body = app.get("body")
        if body and any(t in body for t in ("&lt", "&gt", "&amp", "&#")):
            section["text_decoded"] = html.unescape(body)
            ...

        # T03: SMTP/MIME — header CTE nằm trong payload_b64 (headers + body),
        # smtp_body chỉ có body → tự tách từ payload_b64:
        #   "Content-Transfer-Encoding: base64" → base64.b64decode
        #   "...quoted-printable" → quopri.decodestring
        ...

        # T04: strict UTF-8 decode payload_b64 → fail thì partial + reason
        ...
    except Exception as error:
        section["decode_status"] = "partial"
        section["decode_reason"] = str(error)
    return event
```

Quy tắc:

- Chỉ ghi `event["decoder"]`, không sửa section khác.
- T01: `application.path` **không bao giờ bị sửa** (raw còn nguyên).
- Ưu tiên decode_method theo mức: percent (URI) → html_entity (text) → base64/qp (body) — mỗi event ghi method đã áp; method nào không áp → giữ null/`none`.
- `decode_status`: `ok` khi decode thành công; `partial/error` khi lỗi; `not_applicable` khi event không chứa dữ liệu cần decode (vd DNS).

**Nối vào `main.py`** (import `from decoder import apply as decode_event` hoặc `import decoder` — chọn 1 style và giữ nhất quán), thay comment đầu:

```python
event = decoder.apply(event)
```

Smoke: chạy pcap DNS → không crash, `decode_status` null/not_applicable.

```bash
git add src/decoder.py src/main.py && git commit -m "implement decoder module"
```

### T01 — HTTP URL decode

| | |
|---|---|
| **input.pcap** | 1 packet TCP dport 80, payload `GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\nHost: x\r\n\r\n` |
| **Chạy** | `run_cli` (hoặc pytest tự chạy) → `output.jsonl` |
| **Assert** | `uri_decoded == "/search?q=' OR 1=1"` · `application.path` vẫn `%27%20OR%201%3D1` (raw) · `decode_method == "percent"` · `decode_status == "ok"` |
| **report.md** | so sánh raw vs decoded trong bảng |
| **Commit** | `Test HTTP URL decode -case T01` |

File: `tests/test_t01_url_decode.py`, folder `TEST/T01_HTTP_URL_Decode/`.

### T02 — HTML entity

| | |
|---|---|
| **input.pcap** | HTTP response, body chứa `&lt;script&gt;alert(1)&lt;/script&gt;` |
| **Assert** | `text_decoded == "<script>alert(1)</script>"` · `decode_status == "ok"` · không crash |
| **Commit** | `Test HTML entity -case T02` |

### T03 — SMTP Base64 / Quoted-Printable

| | |
|---|---|
| **input.pcap** | 2 packet TCP dport 25: (1) payload MIME `Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQ=` ; (2) variant quoted-printable `=48=65=6C=6C=6F` |
| **Assert** | packet 1: `body_decoded == "Hello World"`, `decode_method == "base64"`, `decode_status == "ok"` ; packet 2: `== "Hello"`, method `quoted_printable` |
| **Commit** | `Test SMTP base64/qp decode -case T03` |

### T04 — Invalid bytes

| | |
|---|---|
| **input.pcap** | 1 packet TCP, payload b"\xff\xfe\xfa not utf-8" (Raw giữ nguyên byte hỏng) |
| **Assert** | `decode_status in ("partial","error")` · `decode_reason` khác None · event vẫn đủ section (chương trình chạy tiếp) · CLI exit 0 |
| **Commit** | `Test invalid bytes -case T04` |

Regression sau Phase 1: chạy lại T01–T04 + 1 pcap DNS BT01.

---

## 7. Phase 2 — PREPROCESSOR (1 task + T05, T06, T14)

### Task: `preprocessor.apply(event) -> event`

```python
def apply(event):
    section = event["preprocess"]
    try:
        # 1. Validation → valid | partial | invalid
        #    - timestamp là số; port 0..65535; protocol thuộc tập đã biết
        #    - field bắt buộc thiếu → partial (reason ghi rõ)
        #    - vi phạm range/sai kiểu → invalid
        # 2. Normalization → section["normalized"]
        #    - protocol: strip + chuẩn hóa (chốt convention, vd "TCP")
        #    - src_ip/dst_ip: ipaddress.ip_address(x).compressed
        #    - host: .lower().rstrip(".")  ("Example.COM." → "example.com")
        #    - path: giữ case, chỉ chuẩn format
        #    - header_names: [tên.lower() ...] , list rỗng → []
        #    - timestamp: float
        # 3. processing_action theo cấu hình: invalid → skip/continue (mặc định continue)
    except Exception as error:
        section["preprocess_status"] = "invalid"
        section["reason"] = str(error)
        section["processing_action"] = "continue"
    return event
```

Nối vào `main.py` (comment thứ 2):

```bash
git add src/preprocessor.py src/main.py && git commit -m "implement preprocessor module"
```

### T05 — Normalization

| | |
|---|---|
| **input.pcap** | HTTP request `Host: Example.COM.` + header mixed-case `X-CuStOm: VaLue` |
| **Assert** | `normalized.host == "example.com"` · `normalized.protocol` đúng convention · `header_names` toàn lowercase · 2 event khác kiểu chữ input → representation giống hệt nhau |
| **Commit** | `Test normalization -case T05` |

### T06 — Missing field

| | |
|---|---|
| **input.pcap** | Packet TCP chỉ có handshake/payload rỗng → `application` gần như null toàn bộ (mô phỏng event thiếu field không bắt buộc); kèm case unit: `make_event(application=None)` |
| **Assert** | không exception · field thiếu = `null`, list = `[]` · `preprocess_status` theo convention (`valid` với field optional null / `partial` với reason — chốt 1 kiểu) |
| **Commit** | `Test missing field -case T06` |

### T14 — Malformed event

| | |
|---|---|
| **input.pcap** | Packet malformed kiểu BT01 (reuse cách tạo từ `TEST/Testcase12_Malformed_Packet/input.pcap`: truncate/byte lạ) khiến parser sinh `parse_error`; kèm unit: port 99999, timestamp `"not-a-number"`, protocol `"???"` |
| **Assert** | không crash · `preprocess_status == "invalid"` · `reason` trỏ đúng lỗi · `processing_action` theo cấu hình · CLI exit 0, output vẫn ghi đủ dòng |
| **Commit** | `Test malformed event -case T14` |

---

## 8. Phase 3 — FLOW TRACKER (3 task + T07–T13) — module trọng tâm

### Task A: core — 5-tuple, flow_id, direction

```python
class FlowTracker:
    def __init__(self, tcp_timeout=300, udp_timeout=60):
        self.active = {}      # flow_key -> flow dict
        self.closed = []      # đã đóng, chờ ghi flows.jsonl

    def track(self, event):
        # 1. 5-tuple từ network + transport
        # 2. endpoint chuẩn hóa: a, b = sorted([(ip,port),(ip,port)])
        #    → 2 chiều A→B và B→A cùng flow_key (T08)
        # 3. flow_id = f"{protocol}-{a_ip}:{a_port}-{b_ip}:{b_port}" (ổn định)
        # 4. flow mới → direction = "forward" (packet đầu tạo flow)
        #    đã có → forward nếu (src_ip,src_port)==a else backward
        # 5. event["flow"] = {flow_id, direction, state}
        # 6. +packet_count, byte_count += ip_length, forward/backward counts, last_seen
```

- UDP: `state = "NEW"` (§5.3 không có trạng thái kết nối).
- Không có ip_length (packet lạ) → +0, không crash.
- Smoke: pcap DNS 2 packet → cùng flow_id.

```bash
git commit -m "add flow tracker core"
```

### Task B: TCP state machine

```
packet đầu có SYN ("S")              → HANDSHAKE
thấy SYN/ACK ("SA")                  → HANDSHAKE (đánh dấu)
ACK khi đã thấy SA                   → ESTABLISHED
FIN ("F"/"FA") bất kỳ chiều nào      → CLOSING
FIN đủ 2 chiều (forward + backward)  → CLOSED   → đóng ngay, chuyển closed[]
RST ("R")                            → RESET    → đóng ngay
packet đầu không phải SYN            → ESTABLISHED (mid-stream, ghi chú vào README)
```

Cộng `syn_count/ack_count/fin_count/rst_count` từ `transport.flags` (chữ `S`,`A`,`F`,`R` — `"SA"` cộng 2 loại). Chỉ đọc flags, không cần payload.

```bash
git commit -m "add tcp connection state tracking"
```

### Task C: timeout + stats + CLI

- `track()`: `now = event["timestamp"]` → flow nào `now - last_seen > timeout` (TCP/UDP riêng) → đóng, `end_reason="timeout"`, vào `closed[]`, **xóa khỏi `active`** — không sleep, dùng timestamp → test tất định.
- `flush()` cuối pcap: đóng flow còn sống với `end_reason="eof"`.
- Stats §5.4 đầy đủ: `start_time, last_seen, duration = last_seen - start_time`, `application_protocol` từ `application.protocol`.
- `main.py`: tạo **1** `FlowTracker()` trong `capture()`, truyền xuống handler; thêm CLI:
  `--flows flows.jsonl --tcp-timeout 300 --udp-timeout 60`
  Flow đóng → ghi 1 dòng JSON vào file `--flows`.
- Nối `event = tracker.track(event)` (comment cuối).

```bash
git add src/flow_tracker.py src/main.py && git commit -m "add idle timeout and flow statistics"
```

### T07 — TCP handshake

| | |
|---|---|
| **input.pcap** | 3 packet cùng 5-tuple: `flags="S"` → `"SA"` → `"A"`, `pkt.time` tăng dần |
| **Chạy** | `--flows flows.jsonl` |
| **Assert** | 3 event cùng `flow.flow_id` · `state`: HANDSHAKE → HANDSHAKE → **ESTABLISHED** · `events[0].flow.direction == "forward"` |
| **Commit** | `Test TCP handshake -case T07` |

### T08 — Bidirectional flow

| | |
|---|---|
| **input.pcap** | `A:40000→B:80` rồi `B:80→A:40000` (đảo chiều, cùng port) |
| **Assert** | cùng `flow_id` · direction `forward` rồi `backward` · cùng 1 flow record trong flows.jsonl, `packet_count == 2` |
| **Commit** | `Test bidirectional flow -case T08` |

### T09 — TCP close

| | |
|---|---|
| **input.pcap** | flow1: FIN/ACK cả 2 chiều (`"FA"` forward + `"FA"` backward + ACK); flow2: packet `flags="R"` |
| **Assert** | flow1 `state == "CLOSED"` · flow2 `state == "RESET"` · cả 2 trong flows.jsonl · không còn trong `active` |
| **Commit** | `Test TCP close -case T09` |

### T10 — UDP query/response

| | |
|---|---|
| **input.pcap** | DNS query `client:51000→53` + response `53→client:51000` (craft `DNS()/DNSQR()`) |
| **Assert** | đúng 1 flow UDP · `packet_count == 2` · `byte_count == sum(ip_length)` (tính trước từ pcap, **không lấy từ output**) · forward/backward = 1/1 |
| **Commit** | `Test UDP query response -case T10` |

### T11 — Concurrent flows

| | |
|---|---|
| **input.pcap** | `A:1000→B:80`, `A:1001→B:80`, `C:2000→B:80` + 1 packet phản xạ mỗi flow |
| **Assert** | ≥2 `flow_id` khác nhau · mỗi packet vào đúng flow (so 5-tuple → flow_id, không gộp nhầm) · số flow trong flows.jsonl đúng |
| **Commit** | `Test concurrent flows -case T11` |

### T12 — Idle timeout

| | |
|---|---|
| **input.pcap** | 2–3 packet cùng flow, set `pkt.time` chênh > timeout (vd 100.0 → 110.0) |
| **Chạy** | `--udp-timeout 5` (hoặc `--tcp-timeout` với TCP) |
| **Assert** | flow trong flows.jsonl có `end_reason == "timeout"` · không còn trong active (packet cuối không nối lại flow cũ nếu chưa đủ timeout mới — hoặc assert theo spec: flow hết hạn bị loại khỏi bảng) |
| **Commit** | `Test idle timeout -case T12` |

### T13 — Statistics

| | |
|---|---|
| **input.pcap** | Nhiều packet 2 chiều, flags hỗn hợp S/A/F, payload rõ độ dài, `pkt.time` đã biết |
| **Assert** | `packet_count` · `byte_count == sum(ip_length)` · forward/backward packet+byte · `syn_count/ack_count/fin_count/rst_count` khớp flags · `duration == last_seen - start_time` (mọi giá trị tính trước từ pcap, không đọc lại output) |
| **Commit** | `Test statistics -case T13` |

---

## 9. Phase 4 — Tổng kết (1 commit)

- `README.md`: usage mới (`--flows`, `--tcp-timeout`, `--udp-timeout`), cấu trúc output 3 section, convention đã chốt (protocol format, decode_status, on-invalid), mục **Use AI** cập nhật phần mã đã dùng AI.
- Chạy toàn bộ: `.venv/bin/python -m pytest tests/ -q` → xanh.
- `git commit -m "update readme for bai-tap-02"`

---

## 10. Checklist commit (23 commit)

| # | Message |
|---|---|
| 1 | `update gitignore` |
| 2 | `add bai-tap-02 spec` |
| 3 | `add testcase guide` |
| 4 | `implement decoder module` |
| 5–8 | `Test … -case T01` … `-case T04` |
| 9 | `implement preprocessor module` |
| 10–11 | `Test … -case T05`, `-case T06` |
| 12 | `Test … -case T14` |
| 13 | `add flow tracker core` |
| 14 | `add tcp connection state tracking` |
| 15 | `add idle timeout and flow statistics` |
| 16–22 | `Test … -case T07` … `-case T13` |
| 23 | `update readme for bai-tap-02` |

Thứ tự T07→T13 phải sau task A/B/C; T01–T04 sau decoder; T05/T06/T14 sau preprocessor. Không commit dồn.
