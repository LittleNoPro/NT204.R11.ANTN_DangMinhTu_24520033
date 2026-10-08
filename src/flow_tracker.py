"""Module Flow/Connection Tracker.

Gom các packet cùng phiên giao tiếp thành flow hai chiều:
- 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol); hai chiều A→B và B→A
  thuộc cùng một flow, flow_id ổn định
- TCP: NEW/HANDSHAKE → ESTABLISHED → CLOSING → CLOSED/RESET, dùng SYN/ACK/FIN/RST
- UDP: cùng bidirectional 5-tuple trong thời gian hợp lệ là một flow
- Idle timeout cho TCP và UDP; flow hết hạn bị đóng/xuất và giải phóng
- Thống kê: packet/byte count tổng và hai chiều, SYN/ACK/FIN/RST count, duration
"""

FLOW_SECTION_SCHEMA = {
    "flow_id": None,
    "direction": None,   # forward | backward
    "state": None,       # NEW | HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET
}


def new_section():
    """Section flow rỗng cho mỗi event — copy mới, không share reference."""
    return dict(FLOW_SECTION_SCHEMA)
