"""Module Preprocessor.

Kiểm tra và chuẩn hóa dữ liệu để module IDS phía sau nhận biểu diễn nhất quán:
- Validation: field bắt buộc, port/range hợp lệ, timestamp, protocol
  → preprocess_status = valid | partial | invalid
- Normalization: protocol name, IP/domain, HTTP header name, URI/path, timestamp
- Missing/unsupported data: giá trị nhất quán null/[], đánh dấu hoặc bỏ qua
  theo cấu hình (processing_action = continue | skip)
- Metadata: reason khi cần
"""

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
        "header_names": [],        # list → thiếu dữ liệu dùng []
        "timestamp": None,
    },
}


def new_section():
    """Section preprocess rỗng cho mỗi event — copy cả nested normalized."""
    section = {**PREPROCESS_SECTION_SCHEMA}
    section["normalized"] = dict(PREPROCESS_SECTION_SCHEMA["normalized"])
    return section
