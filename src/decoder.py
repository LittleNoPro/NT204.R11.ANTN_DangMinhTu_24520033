"""Module Decoder — Bài tập 2 §3.

Chuyển dữ liệu mã hóa/biểu diễn sang dạng phân tích được nhưng không đổi ý
nghĩa logic của dữ liệu:
- HTTP URL/percent decoding + application/x-www-form-urlencoded
- HTML entity decoding cho dữ liệu text phù hợp
- SMTP/MIME: Base64 và Quoted-Printable khi header chỉ ra encoding
- Character decoding tối thiểu ASCII và UTF-8

Mọi lỗi decode nằm trong decode_status/decode_reason — không raise ra ngoài
pipeline (một packet lỗi không được làm dừng chương trình).
"""

DECODER_SECTION_SCHEMA = {
    "uri_decoded": None,       # URI sau percent-decode (T01)
    "text_decoded": None,      # text sau HTML entity decode (T02)
    "body_decoded": None,      # body SMTP sau Base64/Quoted-Printable (T03)
    "decode_method": None,     # percent | html_entity | base64 | quoted_printable | none
    "decode_status": None,     # ok | partial | error | not_applicable (T03, T04)
    "decode_reason": None,     # lý do partial/error, ví dụ "invalid utf-8 at byte 14"
}


def new_section():
    """Section decoder rỗng cho mỗi event — copy mới, không share reference."""
    return dict(DECODER_SECTION_SCHEMA)
