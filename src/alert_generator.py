from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from src.risk_scorer import score_alert


def build_alert(rule: dict[str, Any], event: dict[str, Any], threat_matches: list[dict[str, Any]]) -> dict[str, Any]:
    risk_score, severity = score_alert(rule, event, threat_matches)
    user_identity = event.get("userIdentity", {})
    alert_seed = "|".join(
        [
            rule["id"],
            str(event.get("eventTime", "")),
            str(event.get("eventName", "")),
            str(event.get("sourceIPAddress", "")),
            str(user_identity.get("arn") or user_identity.get("userName") or user_identity.get("type", "")),
        ]
    )

    return {
        "alert_id": f"ALT-{uuid.uuid5(uuid.NAMESPACE_URL, alert_seed).hex[:12].upper()}",
        "title": rule["title"],
        "severity": severity,
        "risk_score": risk_score,
        "timestamp": event.get("eventTime"),
        "affected_account": event.get("recipientAccountId"),
        "affected_user": _affected_user(user_identity),
        "source_ip": event.get("sourceIPAddress"),
        "aws_region": event.get("awsRegion"),
        "event_name": event.get("eventName"),
        "matched_rule_id": rule["id"],
        "matched_rule_title": rule["title"],
        "threat_intel_context": threat_matches,
        "mitre_attack": rule["mitre_attack"],
        "recommended_action": rule["recommended_action"],
        "false_positive_notes": rule["false_positive"],
        "raw_event": {
            "eventSource": event.get("eventSource"),
            "userAgent": event.get("userAgent"),
            "requestParameters": event.get("requestParameters", {}),
        },
    }


def write_alerts_json(alerts: list[dict[str, Any]], path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(alerts, handle, indent=2)
        handle.write("\n")


def _affected_user(user_identity: dict[str, Any]) -> str:
    return (
        user_identity.get("userName")
        or user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
        or user_identity.get("arn")
        or user_identity.get("type")
        or "unknown"
    )

