from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.ai_summary import generate_rule_based_summary


def generate_markdown_report(alerts: list[dict[str, Any]], output_path: str | Path) -> str:
    report_path = Path(output_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_report(alerts)
    report_path.write_text(content, encoding="utf-8")
    return content


def render_report(alerts: list[dict[str, Any]]) -> str:
    severity_counts = Counter(alert["severity"] for alert in alerts)
    high_critical = [alert for alert in alerts if alert["severity"] in {"high", "critical"}]
    ti_alerts = [alert for alert in alerts if alert.get("threat_intel_context")]
    users = sorted({alert["affected_user"] for alert in alerts if alert.get("affected_user")})
    accounts = sorted({alert["affected_account"] for alert in alerts if alert.get("affected_account")})
    mitre = _mitre_coverage(alerts)

    lines = [
        "# Threat-Driven Cloud Detection Report",
        "",
        "## Executive Summary",
        "",
        generate_rule_based_summary(alerts),
        "",
        "## Alert Overview",
        "",
        f"- Total alerts: {len(alerts)}",
        f"- Critical: {severity_counts.get('critical', 0)}",
        f"- High: {severity_counts.get('high', 0)}",
        f"- Medium: {severity_counts.get('medium', 0)}",
        f"- Low: {severity_counts.get('low', 0)}",
        f"- Threat intelligence matches: {len(ti_alerts)}",
        "",
        "## High and Critical Alerts",
        "",
    ]

    if high_critical:
        lines.extend(
            [
                "| Time | Severity | Rule | User | Source IP | Region | Risk |",
                "| --- | --- | --- | --- | --- | --- | ---: |",
            ]
        )
        for alert in high_critical:
            lines.append(
                f"| {alert['timestamp']} | {alert['severity']} | {alert['matched_rule_title']} | "
                f"{alert['affected_user']} | {alert['source_ip']} | {alert['aws_region']} | {alert['risk_score']} |"
            )
    else:
        lines.append("No high or critical alerts were generated.")

    lines.extend(
        [
            "",
            "## Threat Intelligence Matches",
            "",
        ]
    )
    if ti_alerts:
        lines.extend(["| Indicator | Type | Threat Type | Confidence | Source |", "| --- | --- | --- | ---: | --- |"])
        for alert in ti_alerts:
            for match in alert["threat_intel_context"]:
                lines.append(
                    f"| {match['indicator']} | {match['type']} | {match['threat_type']} | "
                    f"{match['confidence']} | {match['source']} |"
                )
    else:
        lines.append("No alerts matched offline threat-intelligence indicators.")

    lines.extend(
        [
            "",
            "## MITRE ATT&CK Coverage",
            "",
            "| Tactic | Techniques | Alert Count |",
            "| --- | --- | ---: |",
        ]
    )
    for tactic, values in sorted(mitre.items()):
        techniques = ", ".join(sorted(values["techniques"]))
        lines.append(f"| {tactic} | {techniques} | {values['count']} |")

    lines.extend(
        [
            "",
            "## Affected Scope",
            "",
            f"- Accounts: {', '.join(accounts) if accounts else 'None'}",
            f"- Users/roles: {', '.join(users) if users else 'None'}",
            "",
            "## Recommended Next Steps",
            "",
            "- Validate whether each IAM, S3, CloudTrail, and security group change was authorized.",
            "- Review source IP reputation and geolocation for suspicious login and API activity.",
            "- Re-enable CloudTrail logging immediately if it was stopped or deleted.",
            "- Remove public S3 bucket exposure unless explicitly approved.",
            "- Rotate access keys created during suspicious sessions and enforce MFA.",
            "",
            "## False Positive Considerations",
            "",
            "- Administrative automation can create IAM users, keys, and policies during approved deployments.",
            "- Security groups may be opened temporarily during troubleshooting or migration windows.",
            "- Unusual regions can be legitimate when new business units expand cloud usage.",
            "- Threat-intelligence indicators are sample offline data and should be validated before escalation.",
            "",
        ]
    )
    return "\n".join(lines)


def _mitre_coverage(alerts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = defaultdict(lambda: {"techniques": set(), "count": 0})
    for alert in alerts:
        for mapping in alert.get("mitre_attack", []):
            tactic = mapping["tactic"]
            technique = f"{mapping['technique_id']} {mapping['technique']}"
            coverage[tactic]["techniques"].add(technique)
            coverage[tactic]["count"] += 1
    return coverage

