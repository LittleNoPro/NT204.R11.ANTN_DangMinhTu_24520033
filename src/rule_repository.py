"""Module Rule Repository / Indexer.

Lưu rule đã validate và tạo chỉ mục để lấy candidate rules nhanh theo
protocol + port, tránh duyệt toàn bộ rule cho mỗi event.

Chỉ mục (mỗi protocol tcp/udp một bảng, rule "ip" nằm riêng):
- port_index[port]  rule có tập port "liệt kê được" (single/list, không âm)
                     ở phía cần so khớp (xem _index_ports)
- generic           rule port any / range / phủ định → luôn là candidate

Rule "->" ưu tiên index theo dst_port (port dịch vụ); nếu dst_port là any
thì index theo src_port. Rule "<>" khớp cả hai chiều nên tra bằng cả
src_port lẫn dst_port của packet.
"""

from collections import defaultdict


def _enumerable_ports(spec):
    """Danh sách port cụ thể của spec, hoặc None nếu là any/range/phủ định."""
    if spec is None or spec["any"] or spec["negate"]:
        return None
    ports = []
    for lo, hi in spec["ranges"]:
        if lo != hi:
            return None
        ports.append(lo)
    return ports


class RuleRepository:
    def __init__(self):
        self.rules = []                 # mọi rule valid, theo thứ tự nạp
        self.rejected = []              # rule invalid/unsupported/disabled (để báo cáo)
        self.by_sid = {}
        self._order = {}                # sid → thứ tự nạp (sắp xếp candidate)
        self._tables = {
            proto: {"dst": defaultdict(list), "src": defaultdict(list),
                    "either": defaultdict(list), "generic": []}
            for proto in ("tcp", "udp")
        }
        self._ip_rules = []             # protocol ip: mọi packet IPv4

    def add(self, rule, disabled_sids=()):
        """Thêm rule; trả về True nếu rule được đưa vào repository."""
        if rule["status"] != "valid":
            self.rejected.append(rule)
            return False
        if rule["sid"] in disabled_sids:
            rule["status"], rule["reason"] = "disabled", "sid disabled by config"
            self.rejected.append(rule)
            return False
        if rule["sid"] in self.by_sid:
            rule["status"] = "invalid"
            rule["reason"] = f"duplicate sid {rule['sid']}"
            self.rejected.append(rule)
            return False

        self.rules.append(rule)
        self.by_sid[rule["sid"]] = rule
        self._order[rule["sid"]] = len(self._order)
        self._index(rule)
        return True

    def _index(self, rule):
        if rule["protocol"] == "ip":
            self._ip_rules.append(rule)
            return
        table = self._tables[rule["protocol"]]
        dst_ports = _enumerable_ports(rule["dst_port"])
        src_ports = _enumerable_ports(rule["src_port"])

        if rule["direction"] == "<>":
            ports = dst_ports if dst_ports is not None else src_ports
            bucket = table["either"]
        elif dst_ports is not None:
            ports, bucket = dst_ports, table["dst"]
        else:
            ports, bucket = src_ports, table["src"]

        if ports is None:
            table["generic"].append(rule)
        else:
            for port in ports:
                bucket[port].append(rule)

    def candidates(self, event):
        """Candidate rules cho event, giữ thứ tự nạp và không trùng lặp."""
        network = event.get("network") or {}
        transport = event.get("transport") or {}
        found = []
        if network.get("protocol") == "IPv4":
            found += self._ip_rules

        proto = str(transport.get("protocol") or "").lower()
        table = self._tables.get(proto)
        if table is not None:
            sport, dport = transport.get("src_port"), transport.get("dst_port")
            found += table["generic"]
            found += table["dst"].get(dport, [])
            found += table["src"].get(sport, [])
            found += table["either"].get(dport, [])
            found += table["either"].get(sport, [])

        seen, result = set(), []
        for rule in sorted(found, key=lambda r: self._order[r["sid"]]):
            if rule["sid"] not in seen:
                seen.add(rule["sid"])
                result.append(rule)
        return result

    def summary(self):
        counts = defaultdict(int)
        counts["valid"] = len(self.rules)
        for rule in self.rejected:
            counts[rule["status"]] += 1
        return dict(counts)
