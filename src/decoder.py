"""Module Decoder.

Chuyển dữ liệu mã hóa/biểu diễn sang dạng phân tích được nhưng không đổi ý
nghĩa logic của dữ liệu:
- HTTP URL/percent decoding + application/x-www-form-urlencoded
- HTML entity decoding cho dữ liệu text phù hợp
- SMTP/MIME: Base64 và Quoted-Printable khi header chỉ ra encoding
- Character decoding tối thiểu ASCII và UTF-8

Mọi lỗi decode nằm trong decode_status/decode_reason — không raise ra ngoài
pipeline (một packet lỗi không được làm dừng chương trình).
"""

import base64, binascii, html, quopri   
from urllib.parse import unquote, unquote_plus

DECODER_SECTION_SCHEMA = {
    "uri_decoded": None,       # URI sau percent-decode (T01)
    "text_decoded": None,      # text sau HTML entity decode (T02)
    "body_decoded": None,      # body SMTP sau Base64/Quoted-Printable (T03)
    "decode_method": None,     # percent | html_entity | base64 | quoted_printable | none
    "decode_status": None,     # ok | partial | error | not_applicable (T03, T04)
    "decode_reason": None,     # lý do partial/error, ví dụ "invalid utf-8 at byte 14"
}


def new_section():
    return dict(DECODER_SECTION_SCHEMA)


def _percent_decode(uri): 
    path, sep, query = uri.partition('?')
    decoded = unquote(path)
    if sep: 
        decoded += '?' + unquote_plus(query)  
    return decoded


def apply(event):
    section = event['decoder']
    section["decode_status"] = "not_applicable"

    try:
        # T01: percent decode — application.path giữ nguyên raw
        path = (event.get("application") or {}).get("path")
        if path:
            _, _, query = path.partition("?")
            # percent-encoding anywhere, hoặc '+' trong query (x-www-form-urlencoded)
            if "%" in path or "+" in query:
                section["uri_decoded"] = _percent_decode(path)
                section["decode_method"] = "percent"
                section["decode_status"] = "ok"

        # T02: HTML entity trên body text — chỉ decode entity, tag thật giữ nguyên
        body = (event.get("application") or {}).get("body")
        if body and html.unescape(body) != body:
            section["text_decoded"] = html.unescape(body)
            if section["decode_status"] != "ok":     # percent đã set thì không ghi đè
                section["decode_method"] = "html_entity"
                section["decode_status"] = "ok"
    except Exception as error: 
        section["decode_status"] = "error"
        section["decode_reason"] = str(error)

    return event

