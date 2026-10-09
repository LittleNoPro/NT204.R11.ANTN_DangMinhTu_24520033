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


def _decode_mime_body(payload_bytes):
    """Tách headers/body MIME, decode theo header Content-Transfer-Encoding.

    Trả về (body_text, method):
    - (None, None)              không thấy CTE hoặc CTE không hỗ trợ
    - (text, method)            decode thành công UTF-8
    - (None, thông_lỗi)         base64 rác hoặc body không phải UTF-8
    """
    header_bytes, sep, body_bytes = payload_bytes.partition(b"\r\n\r\n")
    if not sep:
        header_bytes, sep, body_bytes = payload_bytes.partition(b"\n\n")
    if not sep:
        return None, None

    cte = None
    for line in header_bytes.decode("ascii", errors="replace").splitlines():
        name, colon, value = line.partition(":")
        if colon and name.strip().lower() == "content-transfer-encoding":
            cte = value.strip().lower()
            break
    if cte is None:
        return None, None

    if cte == "base64":
        # body MIME chuẩn được wrap 76 ký tự/dòng → bỏ whitespace trước khi decode
        raw = base64.b64decode(body_bytes.translate(None, b"\r\n\t "), validate=True)
        method = "base64"
    elif cte == "quoted-printable":
        raw = quopri.decodestring(body_bytes)
        method = "quoted_printable"
    else:
        return None, None

    try:
        return raw.decode("utf-8"), method
    except UnicodeDecodeError as error:
        return None, str(error)


def apply(event):
    section = event['decoder']
    section["decode_status"] = "not_applicable"

    try:
        transport = event.get("transport") or {}

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

        # T03: SMTP/MIME — Base64/Quoted-Printable theo header CTE
        if ((event.get("application") or {}).get("protocol") == "SMTP"
                and transport.get("payload_b64")):
            try:
                payload_bytes = base64.b64decode(transport["payload_b64"])
                decoded, method = _decode_mime_body(payload_bytes)
                if decoded is not None:
                    section["body_decoded"] = decoded
                    section["decode_method"] = method
                    section["decode_status"] = "ok"
                elif method:          # lỗi UTF-8, chi tiết nằm trong method
                    section["decode_status"] = "partial"
                    section["decode_reason"] = method
            except (binascii.Error, UnicodeDecodeError) as error:
                section["decode_status"] = "error"
                section["decode_reason"] = f"mime decode failed: {error}"

        # T04: payload không phải UTF-8 hợp lệ → partial, chương trình chạy tiếp
        if section["decode_status"] == "not_applicable" and transport.get("payload_b64"):
            try:
                base64.b64decode(transport["payload_b64"], validate=True).decode("utf-8")
            except UnicodeDecodeError as error:
                section["decode_status"] = "partial"
                section["decode_reason"] = f"invalid utf-8: {error}"
    except Exception as error: 
        section["decode_status"] = "error"
        section["decode_reason"] = str(error)

    return event

