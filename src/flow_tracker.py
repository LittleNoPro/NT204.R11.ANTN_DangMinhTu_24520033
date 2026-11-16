"""Module Flow/Connection Tracker."""
import itertools

FLOW_SECTION_SCHEMA = {
    "flow_id": None,
    "direction": None,   # forward | backward
    "state": None,       # NEW | HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET
}


def new_section():
    return dict(FLOW_SECTION_SCHEMA)


SERVICE_PORT_MAX = 1023     # port <= 1023 coi là port dịch vụ (phía server)


class FlowTracker:
    """Theo dõi flow đang mở; flow đóng được giao ngay cho `on_close(flow)`.

    Không giữ flow đã đóng trong bộ nhớ, để chạy live nhiều giờ không phình RAM
    và flow đã đóng không bị mất nếu tiến trình dừng đột ngột.
    """

    def __init__(self, tcp_timeout=300, udp_timeout=60, on_close=None):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.on_close = on_close or (lambda flow: None)
        self.active = {}
        self._counter = itertools.count(1)
        self._next_sweep = None         # lần quét timeout kế tiếp (giây, theo giờ packet)
        self.last_flow = None          # flow của packet vừa track (cho context())

    def _key(self, net, tr):
        proto, l4 = net.get("protocol"), tr.get("protocol")
        # sắp xếp theo cặp (ip, port) — sắp IP và port riêng rẽ sẽ gộp nhầm
        # A:1000→B:2000 với A:2000→B:1000 thành một flow
        src = (str(net.get("src_ip")), tr.get("src_port"))
        dst = (str(net.get("dst_ip")), tr.get("dst_port"))
        end_a, end_b = sorted([src, dst])
        return (proto, l4) + end_a + end_b

    @staticmethod
    def _client_is_dst(tr):
        """Packet đầu tiên của flow có phải do server gửi không.

        - SYN-ACK: chắc chắn server gửi (capture bắt đầu giữa lúc bắt tay)
        - SYN không ACK: client gửi
        - TCP bắt giữa chừng (không có SYN): phía dùng port dịch vụ (1–1023)
          là server
        - còn lại (UDP, không đoán được): người gửi packet đầu là client
        """
        if tr.get("protocol") != "TCP":
            return False
        flags = str(tr.get("flags") or "")
        if "S" in flags:
            return "A" in flags
        return 0 < tr.get("src_port") <= SERVICE_PORT_MAX < tr.get("dst_port")

    def _new_flow(self, event, key):
        net, tr = event["network"], event["transport"]
        l4 = tr.get("protocol")
        src = {"ip": net.get("src_ip"), "port": tr.get("src_port")}
        dst = {"ip": net.get("dst_ip"), "port": tr.get("dst_port")}
        client, server = (dst, src) if self._client_is_dst(tr) else (src, dst)
        flow = {
            "flow_id": "flow-{:04d}".format(next(self._counter)),
            "protocol": l4 or net.get("protocol") or "UNKNOWN",
            "application_protocol": None,
            "endpoint_a": client,
            "endpoint_b": server,
            "_initiator": (client["ip"], client["port"]),
            "start_time": event["timestamp"],
            "last_seen": event["timestamp"],
            "packet_count": 0,
            "byte_count": 0,
            "forward": {"packet_count": 0, "byte_count": 0},
            "backward": {"packet_count": 0, "byte_count": 0},
            "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
            "state": "NEW",
            "_saw_syn": False, "_saw_synack": False,
            "_fin_fwd": False, "_fin_bwd": False,
            "end_reason": None,
        }
        # packet đầu không phải SYN → bắt giữa chừng phiên, coi như đã established
        flags = str(tr.get("flags") or "")
        if l4 == "TCP" and "S" not in flags:
            flow["state"] = "ESTABLISHED"
        self.active[key] = flow
        return flow

    def _update_tcp_state(self, flow, flags, direction):
        if "R" in flags:
            flow["state"] = "RESET"
            return True                     # đóng ngay
        if "S" in flags:
            flow["state"] = "HANDSHAKE"
            flow["_saw_syn"] = True
            if "A" in flags:
                flow["_saw_synack"] = True
        elif flow["state"] in ("NEW", "HANDSHAKE") and "A" in flags:
            if flow["_saw_syn"] and flow["_saw_synack"]:
                flow["state"] = "ESTABLISHED"
            elif not flow["_saw_syn"]:
                flow["state"] = "ESTABLISHED"   # mid-stream
        if "F" in flags:
            flow["state"] = "CLOSING" if flow["state"] != "RESET" else "RESET"
            if direction == "forward":
                flow["_fin_fwd"] = True
            else:
                flow["_fin_bwd"] = True
            if flow["_fin_fwd"] and flow["_fin_bwd"]:
                flow["state"] = "CLOSED"       # vẫn giữ trong bảng → ACK cuối vẫn vào flow
        return "R" in flags

    def _idle(self, flow, now):
        timeout = self.tcp_timeout if flow["protocol"] == "TCP" else self.udp_timeout
        return now - flow["last_seen"] > timeout

    def _expire(self, now):
        """Đóng flow quá idle timeout. Chỉ quét toàn bảng tối đa 1 lần/giây
        (theo giờ packet) — quét mỗi packet tốn O(số flow) cho từng packet."""
        if self._next_sweep is not None and now < self._next_sweep:
            return
        self._next_sweep = now + 1
        for key in [k for k, f in self.active.items() if self._idle(f, now)]:
            self._close(key, self.active[key], "timeout")

    def _close(self, key, flow, reason):
        self.active.pop(key, None)
        flow["end_reason"] = reason
        flow["duration"] = max(0.0, flow["last_seen"] - flow["start_time"])
        for field in ("_initiator", "_saw_syn", "_saw_synack", "_fin_fwd", "_fin_bwd"):
            flow.pop(field, None)
        self.on_close(flow)

    def track(self, event):
        net, tr = event.get("network") or {}, event.get("transport") or {}
        # flow định nghĩa theo 5-tuple → chỉ track TCP/UDP có đủ IP + port;
        # packet khác (ICMP, non-IP, malformed) giữ flow = null
        if (tr.get("protocol") not in ("TCP", "UDP")
                or not net.get("src_ip") or not net.get("dst_ip")
                or not isinstance(tr.get("src_port"), int)
                or not isinstance(tr.get("dst_port"), int)):
            event["flow"] = new_section()
            return event
        try:
            now = event["timestamp"]
            self._expire(now)
            key = self._key(net, tr)
            flags = str(tr.get("flags") or "")
            flow = self.active.get(key)
            if flow is not None and self._idle(flow, now):
                self._close(key, flow, "timeout")       # quét timeout chưa tới lượt
                flow = None
            elif (flow is not None and flow["state"] == "CLOSED"
                  and "S" in flags and "A" not in flags):
                self._close(key, flow, "closed")        # SYN mới cùng port → kết nối mới
                flow = None
            if flow is None:
                flow = self._new_flow(event, key)

            direction = ("forward"
                         if (net.get("src_ip"), tr.get("src_port"))
                         == flow["_initiator"] else "backward")

            l4 = tr.get("protocol")
            if l4 == "TCP":
                for flag, field in (("S", "syn_count"), ("A", "ack_count"),
                                    ("F", "fin_count"), ("R", "rst_count")):
                    if flag in flags:
                        flow[field] += 1
                closing = self._update_tcp_state(flow, flags, direction)
            elif l4 == "UDP":
                flow["state"] = "NEW"
                closing = False
            else:
                closing = False

            flow["packet_count"] += 1
            bucket = flow["forward"] if direction == "forward" else flow["backward"]
            bucket["packet_count"] += 1

            nbytes = net.get("ip_length") or 0
            flow["byte_count"] += nbytes
            bucket["byte_count"] += nbytes

            flow["last_seen"] = max(flow["last_seen"], now)
            flow["start_time"] = min(flow["start_time"], now)
            app_proto = (event.get("application") or {}).get("protocol")
            if app_proto and app_proto != "UNKNOWN":
                flow["application_protocol"] = app_proto

            self.last_flow = flow
            if closing:
                self._close(key, flow,
                            "reset" if flow["state"] == "RESET" else "closed")

            event["flow"] = {"flow_id": flow["flow_id"],
                             "direction": direction,
                             "state": flow["state"]}
        except Exception as error:
            event["flow"] = new_section()
            pre = event.setdefault("preprocess", {})
            message = f"flow tracking error: {error}"
            pre["reason"] = f"{pre['reason']}; {message}" if pre.get("reason") else message
        return event

    def context(self, event):
        """Flow context cho Core Engine của packet vừa được track.

        - to_server/to_client: theo direction (forward = phía khởi tạo → server)
        - established: TCP ở ESTABLISHED/CLOSING; UDP khi đã thấy cả hai chiều
        """
        info = event.get("flow") or {}
        flow = self.last_flow
        if not info.get("flow_id") or flow is None or flow["flow_id"] != info["flow_id"]:
            return {"flow_id": None, "direction": None, "state": None,
                    "to_server": False, "to_client": False, "established": False,
                    "application_protocol": None}
        if flow["protocol"] == "TCP":
            established = flow["state"] in ("ESTABLISHED", "CLOSING")
        else:
            established = (flow["forward"]["packet_count"] > 0
                           and flow["backward"]["packet_count"] > 0)
        return {
            "flow_id": flow["flow_id"],
            "direction": info["direction"],
            "state": flow["state"],
            "to_server": info["direction"] == "forward",
            "to_client": info["direction"] == "backward",
            "established": established,
            "application_protocol": flow["application_protocol"],
        }

    def flush(self):
        """Đóng mọi flow còn mở (khi kết thúc capture)."""
        for key, flow in list(self.active.items()):
            self._close(key, flow, "closed" if flow["state"] == "CLOSED" else "eof")