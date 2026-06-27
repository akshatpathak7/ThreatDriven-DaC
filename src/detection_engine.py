from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from src.alert_generator import build_alert
from src.threat_intel import ThreatIntelStore


class DetectionEngine:
    def __init__(self, rules: list[dict[str, Any]], threat_intel: ThreatIntelStore | None = None) -> None:
        self.rules = rules
        self.threat_intel = threat_intel or ThreatIntelStore()

    def run(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for rule in self.rules:
            threshold = rule.get("detection", {}).get("threshold")
            if threshold:
                alerts.extend(self._run_threshold_rule(rule, events, threshold))
                continue

            for event in events:
                if self._event_matches_rule(event, rule):
                    threat_matches = self.threat_intel.enrich_event(event)
                    alerts.append(build_alert(rule, event, threat_matches))

        return sorted(alerts, key=lambda alert: (alert["timestamp"] or "", alert["matched_rule_id"]))

    def _run_threshold_rule(
        self, rule: dict[str, Any], events: list[dict[str, Any]], threshold: dict[str, Any]
    ) -> list[dict[str, Any]]:
        matching_events = [event for event in events if self._event_matches_rule(event, rule)]
        group_by = threshold.get("group_by")
        minimum = int(threshold.get("count", 1))
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for event in matching_events:
            key = str(get_nested_value(event, group_by)) if group_by else "__all__"
            groups[key].append(event)

        alerts: list[dict[str, Any]] = []
        for grouped_events in groups.values():
            for window in _threshold_windows(grouped_events, int(threshold.get("timeframe_minutes", 60))):
                if len(window) >= minimum:
                    representative = window[-1]
                    threat_matches = self.threat_intel.enrich_event(representative)
                    alert = build_alert(rule, representative, threat_matches)
                    alert["threshold_context"] = {
                        "count": len(window),
                        "minimum": minimum,
                        "timeframe_minutes": int(threshold.get("timeframe_minutes", 60)),
                    }
                    alerts.append(alert)
                    break
        return alerts

    def _event_matches_rule(self, event: dict[str, Any], rule: dict[str, Any]) -> bool:
        detection = rule["detection"]
        selection = detection["selection"]
        condition = detection.get("condition", "selection")

        selection_result = all(
            match_value(get_nested_value(event, field), expected, self.threat_intel)
            for field, expected in selection.items()
        )

        filters = detection.get("filter", {})
        filter_result = bool(filters) and all(
            match_value(get_nested_value(event, field), expected, self.threat_intel)
            for field, expected in filters.items()
        )

        if condition == "selection":
            return selection_result
        if condition == "selection and not filter":
            return selection_result and not filter_result
        if condition == "selection and filter":
            return selection_result and filter_result
        raise ValueError(f"Unsupported condition {condition!r} in rule {rule['id']}")


def get_nested_value(event: dict[str, Any], field_path: str | None) -> Any:
    if not field_path:
        return None
    current: Any = event
    for part in field_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            values = []
            for item in current:
                if isinstance(item, dict) and part in item:
                    values.append(item[part])
            current = values
        else:
            return None
    return current


def match_value(actual: Any, expected: Any, threat_intel: ThreatIntelStore | None = None) -> bool:
    if isinstance(expected, dict):
        if "equals" in expected:
            return _equals(actual, expected["equals"])
        if "contains" in expected:
            return _contains(actual, expected["contains"])
        if "contains_any" in expected:
            return any(_contains(actual, value) for value in expected["contains_any"])
        if "in" in expected:
            return _in(actual, expected["in"])
        if "not_in" in expected:
            return not _in(actual, expected["not_in"])
        if "exists" in expected:
            return (actual is not None) is bool(expected["exists"])
        if "ioc_match" in expected:
            if threat_intel is None:
                return False
            return threat_intel.find(actual, expected["ioc_match"]) is not None
        raise ValueError(f"Unsupported detection operator: {expected}")
    return _equals(actual, expected)


def _equals(actual: Any, expected: Any) -> bool:
    if isinstance(actual, list):
        return any(_equals(item, expected) for item in actual)
    return actual == expected


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, list):
        return any(_contains(item, expected) for item in actual)
    if isinstance(actual, dict):
        actual_text = json.dumps(actual, sort_keys=True)
    else:
        actual_text = str(actual)
    return str(expected).lower() in actual_text.lower()


def _in(actual: Any, expected_values: list[Any]) -> bool:
    if isinstance(actual, list):
        return any(item in expected_values for item in actual)
    return actual in expected_values


def _threshold_windows(events: list[dict[str, Any]], timeframe_minutes: int) -> list[list[dict[str, Any]]]:
    sorted_events = sorted(events, key=lambda event: event.get("eventTime", ""))
    windows: list[list[dict[str, Any]]] = []
    for index, event in enumerate(sorted_events):
        start = _parse_time(event.get("eventTime"))
        if start is None:
            continue
        end = start + timedelta(minutes=timeframe_minutes)
        window = [
            candidate
            for candidate in sorted_events[index:]
            if (candidate_time := _parse_time(candidate.get("eventTime"))) is not None and start <= candidate_time <= end
        ]
        windows.append(window)
    return windows


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

