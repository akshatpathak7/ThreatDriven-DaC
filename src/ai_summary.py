from __future__ import annotations

from collections import Counter
from typing import Any


def generate_rule_based_summary(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "No suspicious cloud activity was detected in the analyzed sample logs."

    severity_counts = Counter(alert["severity"] for alert in alerts)
    top_alert = max(alerts, key=lambda alert: alert["risk_score"])
    users = sorted({alert["affected_user"] for alert in alerts if alert.get("affected_user")})
    ti_matches = sum(1 for alert in alerts if alert.get("threat_intel_context"))

    return (
        f"The pipeline generated {len(alerts)} alert(s), including "
        f"{severity_counts.get('critical', 0)} critical and {severity_counts.get('high', 0)} high severity finding(s). "
        f"The highest-risk activity was '{top_alert['title']}' affecting {top_alert['affected_user']} "
        f"from {top_alert['source_ip']}. {ti_matches} alert(s) matched offline threat-intelligence indicators. "
        f"Security teams should validate the affected identities ({', '.join(users[:5])}), review CloudTrail and IAM changes, "
        "rotate exposed credentials where needed, and confirm whether the activity was authorized."
    )

