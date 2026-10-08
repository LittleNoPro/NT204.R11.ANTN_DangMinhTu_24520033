"""Pipeline Bài tập 2: parse → decode → preprocess → track.

Mỗi stage là hàm thuần `event → event`, chỉ sửa section của mình, không bao giờ
raise: lỗi nội bộ được ghi vào status/reason của section đó để event vẫn đi
tiếp qua các stage sau.

Hiện tại mới có scaffold section (schema đầy đủ, giá trị null); các module
Decoder / Preprocessor / FlowTracker sẽ nối vào đây từng task.
"""

DECODER_SECTION_SCHEMA = {
    # HTTP URL / percent decoding
    "uri_raw": None,
    "uri_decoded": None,
    # HTML entity decoding (text phù hợp)
    "text_decoded": None,
    # SMTP/MIME base64 / quoted-printable
    "body_decoded": None,
    "decode_method": None,     # percent | html_entity | base64 | quoted_printable | none
    "decode_status": None,     # ok | partial | error | not_applicable
    "decode_reason": None,
}

PREPROCESS_SECTION_SCHEMA = {
    "preprocess_status": None,     # valid | partial | invalid
    "processing_action": None,     # continue | skip
    "reason": None,
    "normalized": {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "host": None,
        "path": None,
        "header_names": [],        # list → thiếu dữ liệu dùng [] (yêu cầu §4)
        "timestamp": None,
    },
}

FLOW_SECTION_SCHEMA = {
    "flow_id": None,
    "direction": None,   # forward | backward
    "state": None,       # NEW | HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET
}


def _init_sections(event):
    """Gắn 3 section vào event với giá trị mặc định từ schema."""
    event["decoder"] = dict(DECODER_SECTION_SCHEMA)
    event["preprocess"] = dict(PREPROCESS_SECTION_SCHEMA)
    event["preprocess"]["normalized"] = dict(PREPROCESS_SECTION_SCHEMA["normalized"])
    event["flow"] = dict(FLOW_SECTION_SCHEMA)
    return event


def run_event(event):
    """Đưa một event qua toàn bộ pipeline.

    Thay `return event` bằng chuỗi gọi stage khi module hoàn thành:
        event = decoder.apply(event, cfg)
        event = preprocessor.apply(event, cfg)
        event = tracker.track(event, cfg)
    """
    event = _init_sections(event)
    return event
