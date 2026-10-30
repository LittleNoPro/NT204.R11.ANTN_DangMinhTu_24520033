"""Module Rule Loader.

Đọc một hoặc nhiều file .rules (cú pháp Snort):
- bỏ dòng trống và comment (dòng bắt đầu bằng '#')
- nối rule viết trên nhiều dòng bằng '\\' ở cuối dòng
- enable/disable file rule hoặc từng sid bằng file cấu hình JSON
- file không đọc được → cảnh báo, vẫn nạp các file còn lại

Loader chỉ trả về rule text (kèm vị trí file/dòng); việc parse/validate do
rule_parser đảm nhiệm. Không có signature nào hard-code trong source code.

Cấu hình (rules/engine.json):
{
  "rule_files": [{"path": "rules/local.rules", "enabled": true}, ...],
  "disabled_sids": [1000005],
  "variables": {"HOME_NET": "any", "HTTP_PORTS": "[80,8080]"}
}
"""

import json
import os


DEFAULT_CONFIG = {
    "rule_files": [],
    "disabled_sids": [],
    "variables": {},
}


def load_config(path):
    """Đọc file cấu hình JSON; đường dẫn rule_files tính tương đối theo file config."""
    config = {**DEFAULT_CONFIG}
    if not path:
        return config
    with open(path, encoding="utf-8") as f:
        config.update(json.load(f))
    base = os.path.dirname(os.path.abspath(path))
    files = []
    for item in config["rule_files"]:
        if isinstance(item, str):
            item = {"path": item, "enabled": True}
        rule_path = item["path"]
        if not os.path.isabs(rule_path) and not os.path.exists(rule_path):
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
