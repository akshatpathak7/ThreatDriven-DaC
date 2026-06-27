from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REQUIRED_RULE_FIELDS = {
    "id",
    "title",
    "description",
    "logsource",
    "detection",
    "severity",
    "risk_score",
    "mitre_attack",
    "false_positive",
    "recommended_action",
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def load_rule(path: str | Path) -> dict[str, Any]:
    rule_path = Path(path)
    with rule_path.open("r", encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)
    if not isinstance(rule, dict):
        raise ValueError(f"{rule_path} must contain a YAML object")
    validate_rule_schema(rule, source=str(rule_path))
    return rule


def load_rules(directory: str | Path) -> list[dict[str, Any]]:
    rules_dir = Path(directory)
    rules = [load_rule(path) for path in sorted(rules_dir.glob("*.yml"))]
    ids = [rule["id"] for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise ValueError(f"Duplicate rule ids found: {', '.join(duplicates)}")
    return rules


def validate_rule_schema(rule: dict[str, Any], source: str = "<memory>") -> None:
    missing = REQUIRED_RULE_FIELDS - set(rule)
    if missing:
        raise ValueError(f"{source} is missing required fields: {', '.join(sorted(missing))}")

    if rule["severity"] not in VALID_SEVERITIES:
        raise ValueError(f"{source} has invalid severity {rule['severity']!r}")

    if not isinstance(rule["risk_score"], int) or not 0 <= rule["risk_score"] <= 100:
        raise ValueError(f"{source} risk_score must be an integer from 0 to 100")

    if not isinstance(rule["detection"], dict) or "selection" not in rule["detection"]:
        raise ValueError(f"{source} detection must include a selection block")

    if not isinstance(rule["detection"]["selection"], dict):
        raise ValueError(f"{source} detection.selection must be a mapping")

    if not isinstance(rule["mitre_attack"], list) or not rule["mitre_attack"]:
        raise ValueError(f"{source} mitre_attack must be a non-empty list")

    for mapping in rule["mitre_attack"]:
        if not isinstance(mapping, dict):
            raise ValueError(f"{source} mitre_attack entries must be mappings")
        for field in ("tactic", "technique_id", "technique"):
            if field not in mapping:
                raise ValueError(f"{source} mitre_attack entries must include {field}")

