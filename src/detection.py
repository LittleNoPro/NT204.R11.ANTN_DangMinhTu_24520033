"""Module Detection Event Generator.

Sinh Detection Event thống nhất khi một rule MATCH; Alert/Logging/Response ở
bài tập sau chỉ cần đọc cấu trúc này, không cần biết rule hay packet gốc.
"""

DETECTION_EVENT_SCHEMA = {
    "timestamp": None,
    "packet_id": None,
    "sid": None, "rev": None, "msg": None,
    "priority": None, "classtype": None,
    "protocol": None,                 # TCP | UDP | ...
    "application_protocol": None,     # HTTP | DNS | SMTP | null
    "src_ip": None, "src_port": None,
    "dst_ip": None, "dst_port": None,
    "flow_id": None, "flow_direction": None, "flow_state": None,
    "match": {},                      # content/flow/flags/dsize đã khớp
}


def generate(rule, event, flow_ctx, match_result):
    network = event.get("network") or {}
    transport = event.get("transport") or {}
    application = event.get("application") or {}
    norm = (event.get("preprocess") or {}).get("normalized") or {}
    ctx = flow_ctx or {}

    app_proto = application.get("protocol")
    if app_proto in (None, "UNKNOWN"):
        app_proto = ctx.get("application_protocol")

    return {
        **DETECTION_EVENT_SCHEMA,
        "timestamp": event.get("timestamp"),
        "packet_id": event.get("packet_id"),
        "sid": rule["sid"], "rev": rule["rev"], "msg": rule["msg"],
        "priority": rule["priority"], "classtype": rule["classtype"],
        "protocol": transport.get("protocol") or network.get("protocol"),
        "application_protocol": app_proto,
        "src_ip": norm.get("src_ip") or network.get("src_ip"),
        "src_port": transport.get("src_port"),
        "dst_ip": norm.get("dst_ip") or network.get("dst_ip"),
        "dst_port": transport.get("dst_port"),
        "flow_id": ctx.get("flow_id"),
        "flow_direction": ctx.get("direction"),
        "flow_state": ctx.get("state"),
        "match": match_result["matched"],
    }
