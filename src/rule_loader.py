"""Module Rule Loader.

Đọc một hoặc nhiều file .rules (cú pháp Snort):
- bỏ dòng trống và comment (dòng bắt đầu bằng '#')
- nối rule viết trên nhiều dòng bằng '\\' ở cuối dòng
- enable/disable file rule hoặc từng sid bằng file cấu hình JSON
- file không đọc được → cảnh báo, vẫn nạp các file còn lại

Loader chỉ trả về rule text (kèm vị trí file/dòng); việc parse/validate do
rule_parser đảm nhiệm. Không có signature nào hard-code trong source code.

File cấu hình của IDS (rules/engine.json, truyền bằng -c):
{
  "rule_files": [{"path": "local.rules", "enabled": true}, ...],
  "disabled_sids": [1000005],
  "variables": {"HOME_NET": "any", "HTTP_PORTS": "[80,8080]"},
  "flow_timeout": {"tcp": 300, "udp": 60},     # giây rảnh trước khi đóng flow
  "skip_unknown": false,     # không đánh giá event có protocol ứng dụng UNKNOWN
  "max_payload": null        # không đánh giá payload lớn hơn N byte (null = không giới hạn)
}
Đường dẫn trong rule_files tính tương đối theo thư mục chứa file cấu hình.
"""

import json
import os


DEFAULT_CONFIG = {
    "rule_files": [],
    "disabled_sids": [],
    "variables": {},
    "flow_timeout": {"tcp": 300, "udp": 60},
    "skip_unknown": False,
    "max_payload": None,
}


class ConfigError(ValueError):
    """File cấu hình không đọc được hoặc có giá trị sai kiểu."""


def _check(ok, message):
    if not ok:
        raise ConfigError(message)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_config(path):
    """Đọc file cấu hình JSON, điền giá trị mặc định cho khóa thiếu và kiểm tra kiểu.

    Sai kiểu phải báo ngay lúc khởi động: ví dụ "max_payload": "200" (chuỗi) nếu để
    lọt sẽ làm Preprocessor lỗi trên mọi packet và IDS không đánh giá packet nào.
    Đường dẫn trong rule_files tính tương đối theo thư mục chứa file cấu hình.
    """
    config = {**DEFAULT_CONFIG, "flow_timeout": dict(DEFAULT_CONFIG["flow_timeout"])}
    if not path:
        return config
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as error:
        raise ConfigError(f"không đọc được {path}: {error.strerror}")
    except json.JSONDecodeError as error:
        raise ConfigError(f"{path}: JSON sai cú pháp ({error})")

    _check(isinstance(data, dict), f"{path}: phải là một object JSON")
    unknown = sorted(set(data) - set(DEFAULT_CONFIG))
    _check(not unknown, f"{path}: khóa không hợp lệ {unknown}")
    timeouts = data.pop("flow_timeout", {})
    _check(isinstance(timeouts, dict) and set(timeouts) <= {"tcp", "udp"},
           f'{path}: flow_timeout phải có dạng {{"tcp": giây, "udp": giây}}')
    config["flow_timeout"].update(timeouts)
    config.update(data)

    _check(all(_is_number(v) and v > 0 for v in config["flow_timeout"].values()),
           f"{path}: flow_timeout phải là số giây > 0")
    _check(isinstance(config["skip_unknown"], bool), f"{path}: skip_unknown phải là true/false")
    _check(config["max_payload"] is None
           or (isinstance(config["max_payload"], int) and not isinstance(config["max_payload"], bool)
               and config["max_payload"] >= 0),
           f"{path}: max_payload phải là số byte >= 0 hoặc null")
    _check(isinstance(config["disabled_sids"], list)
           and all(isinstance(sid, int) for sid in config["disabled_sids"]),
           f"{path}: disabled_sids phải là danh sách số")
    _check(isinstance(config["variables"], dict), f"{path}: variables phải là object")
    _check(isinstance(config["rule_files"], list), f"{path}: rule_files phải là danh sách")

    base = os.path.dirname(os.path.abspath(path))
    files = []
    for item in config["rule_files"]:
        if isinstance(item, str):
            item = {"path": item, "enabled": True}
        _check(isinstance(item, dict) and isinstance(item.get("path"), str),
               f"{path}: mỗi mục rule_files cần có \"path\"")
        rule_path = item["path"]
        if not os.path.isabs(rule_path):
            rule_path = os.path.relpath(os.path.join(base, rule_path))
        files.append({"path": rule_path, "enabled": item.get("enabled", True)})
    config["rule_files"] = files
    return config


def read_rule_lines(path):
    """Sinh (line_no, rule_text) cho mỗi rule trong file, bỏ comment/dòng trống."""
    buffer, start = "", None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not buffer and (not line or line.startswith("#")):
                continue
            if start is None:
                start = line_no
            if line.endswith("\\"):            # rule viết tiếp ở dòng sau
                buffer += line[:-1] + " "
                continue
            yield start, buffer + line
            buffer, start = "", None
    if buffer:                                   # file kết thúc giữa rule
        yield start, buffer.strip()


def load_rules(rule_files=(), config=None):
    """Đọc mọi file rule đang bật.

    Trả về (entries, warnings):
    - entries: list {"file", "line", "text"} — rule text chờ parse
    - warnings: list chuỗi cảnh báo (file lỗi, file bị tắt...)
    """
    config = config or DEFAULT_CONFIG
    files = list(config.get("rule_files", []))
    files += [{"path": p, "enabled": True} for p in rule_files]

    entries, warnings = [], []
    for item in files:
        path = item["path"]
        if not item.get("enabled", True):
            warnings.append(f"{path}: file disabled by config")
            continue
        try:
            for line_no, text in read_rule_lines(path):
                entries.append({"file": path, "line": line_no, "text": text})
        except OSError as error:
            warnings.append(f"{path}: cannot read rule file ({error})")
    return entries, warnings
