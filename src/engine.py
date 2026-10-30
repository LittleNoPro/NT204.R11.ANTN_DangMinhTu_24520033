"""Module Rule Evaluation Engine.

Pipeline:
    Normalized Event + Flow Context → Evaluation Engine → Repository/Indexer
        → Matching Engine → Detection Event

- Lấy candidate rules từ Repository/Indexer, gọi Matching Engine cho từng rule.
- Nhiều rule được phép cùng match một event (không dừng ở match đầu tiên).
- Event bị Preprocessor đánh dấu processing_action=skip thì không đánh giá.
- Thống kê: số event đã đánh giá/bỏ qua, số candidate, số lần bị loại ở mỗi
  bước, số match.
"""

from collections import Counter

import detection
import rule_loader
import rule_matcher
import rule_parser
from rule_repository import RuleRepository


def build_repository(rule_files=(), config_path=None):
    """Loader → Parser/Validator → Repository. Trả về (repo, warnings)."""
    config = rule_loader.load_config(config_path)
    entries, warnings = rule_loader.load_rules(rule_files, config)
    repo = RuleRepository()
    disabled = set(config.get("disabled_sids", []))
    for entry in entries:
        rule = rule_parser.parse_rule(entry["text"], entry["file"], entry["line"],
                                      config.get("variables"))
        if not repo.add(rule, disabled):
            warnings.append(f"{entry['file']}:{entry['line']}: "
                            f"{rule['status']} rule (sid={rule['sid']}): {rule['reason']}")
    return repo, warnings


class RuleEngine:
    def __init__(self, repository, skip_invalid=True):
        self.repository = repository
        self.skip_invalid = skip_invalid
        self.stats = Counter()

    def evaluate(self, event, flow_ctx):
        """Trả về (detections, trace) cho một event."""
        trace = {"packet_id": event.get("packet_id"), "skipped": False,
                 "candidates": [], "results": []}
        action = (event.get("preprocess") or {}).get("processing_action")
        if self.skip_invalid and action == "skip":
            self.stats["events_skipped"] += 1
            trace["skipped"] = True
            return [], trace

        self.stats["events_evaluated"] += 1
        candidates = self.repository.candidates(event)
        self.stats["candidate_rules"] += len(candidates)
        trace["candidates"] = [rule["sid"] for rule in candidates]

        detections = []
        for rule in candidates:
            result = rule_matcher.match(rule, event, flow_ctx)
            trace["results"].append({k: result[k] for k in ("sid", "result", "stage", "reason")})
            if result["result"] == "MATCH":
                self.stats["matches"] += 1
                detections.append(detection.generate(rule, event, flow_ctx, result))
            else:
                self.stats[f"rejected_{result['stage']}"] += 1
        return detections, trace

    def summary(self):
        return {"rules_loaded": len(self.repository.rules), **self.stats}
