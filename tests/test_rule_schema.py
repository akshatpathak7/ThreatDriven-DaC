from pathlib import Path

from src.rule_loader import load_rules, validate_rule_schema


def test_all_rules_validate() -> None:
    rules = load_rules("rules")

    assert len(rules) == 10
    for rule in rules:
        validate_rule_schema(rule)


def test_rule_ids_are_unique() -> None:
    rules = load_rules("rules")
    ids = [rule["id"] for rule in rules]

    assert len(ids) == len(set(ids))
    assert len(list(Path("rules").glob("*.yml"))) == 10
