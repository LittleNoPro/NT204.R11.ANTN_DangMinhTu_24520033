"""Module Flow/Connection Tracker."""
import itertools

FLOW_SECTION_SCHEMA = {
    "flow_id": None,
    "direction": None,   # forward | backward
    "state": None,       # NEW | HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET
}


def new_section():
    return dict(FLOW_SECTION_SCHEMA)


TCP_STATES = ("NEW", "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET")


class FlowTracker:
    def __init__(self, tcp_timeout=300, udp_timeout=60):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.active = {}
        self.closed = []
        self._counter = itertools.count(1)

    def _key(self, net, tr):
        proto = net.get("protocol") == "IPv6" and "IPv6" or net.get("protocol")
        l4 = tr.get("protocol")
        ip_a, ip_b = sorted([str(net.get("src_ip") or "?"), str(net.get("dst_ip") or "?")])
        port_a, port_b = sorted([tr.get("src_port"), tr.get("dst_port")])
        if l4 in ("TCP", "UDP"):
            return (proto, l4, ip_a, ip_b, port_a, port_b)
        return (proto, l4, ip_a, ip_b, None, None)

    def _new_flow(self, event, key):
        net, tr = event["network"], event["transport"]
        l4 = tr.get("protocol")
        flow = {
            "flow_id": "flow-{:04d}".format(next(self._counter)),
            "protocol": l4 or net.get("protocol") or "UNKNOWN",
            "application_protocol": None,
            "endpoint_a": {"ip": net.get("src_ip"), "port": tr.get("src_port")},
            "endpoint_b": {"ip": net.get("dst_ip"), "port": tr.get("dst_port")},
            "_initiator": (net.get("src_ip"), tr.get("src_port")),
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

    def _expire(self, now):
        for key in [k for k, f in self.active.items()
                    if now - f["last_seen"] > (self.tcp_timeout
                                               if f["protocol"] == "TCP"
                                               else self.udp_timeout)]:
            flow = self.active.pop(key)
            flow["end_reason"] = "timeout"
            self._append_closed(flow)
            self.closed.append(flow)

    @staticmethod
    def _append_closed(flow):
        flow["duration"] = max(0.0, flow["last_seen"] - flow["start_time"])
        flow.pop("_initiator", None)
        flow.pop("_saw_syn", None)
        flow.pop("_saw_synack", None)
        flow.pop("_fin_fwd", None)
        flow.pop("_fin_bwd", None)

    def _close(self, key, flow, reason):
        self.active.pop(key, None)
        flow["end_reason"] = reason
        self._append_closed(flow)
        self.closed.append(flow)

    def track(self, event):
        net, tr = event.get("network") or {}, event.get("transport") or {}
        try:
            now = event["timestamp"]
            self._expire(now)
            key = self._key(net, tr)
            flow = self.active.get(key) or self._new_flow(event, key)

            direction = ("forward"
                         if (net.get("src_ip"), tr.get("src_port"))
                         == flow["_initiator"] else "backward")

            l4 = tr.get("protocol")
            flags = str(tr.get("flags") or "")
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

            if closing:
                self._close(key, flow,
                            "reset" if flow["state"] == "RESET" else "closed")

            event["flow"] = {"flow_id": flow["flow_id"],
                             "direction": direction,
                             "state": flow["state"]}
        except Exception as error:
            event["flow"] = {"flow_id": None, "direction": None, "state": None}
            event.setdefault("preprocess", {}).setdefault("reason", None)
        return event

    def flush(self):
        for key in list(self.active):
            flow = self.active.pop(key)
            flow["end_reason"] = ("closed" if flow["state"] == "CLOSED"
                                  else "eof")
            self._append_closed(flow)
            self.closed.append(flow)
        return list(self.closed)