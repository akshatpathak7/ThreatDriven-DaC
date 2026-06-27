from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from src.pipeline import run_detection_pipeline
from src.report_generator import render_report


LOG_SETS = {
    "Suspicious sample": ["data/logs/cloudtrail_suspicious.json"],
    "Benign sample": ["data/logs/cloudtrail_benign.json"],
    "Both samples": ["data/logs/cloudtrail_benign.json", "data/logs/cloudtrail_suspicious.json"],
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def severity_counts(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(alert["severity"] for alert in alerts)
    return {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER}


def threat_intel_match_count(alerts: list[dict[str, Any]]) -> int:
    return sum(1 for alert in alerts if alert.get("threat_intel_context"))


def mitre_coverage_rows(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = defaultdict(lambda: {"techniques": set(), "alert_count": 0})
    for alert in alerts:
        for mapping in alert.get("mitre_attack", []):
            tactic = mapping["tactic"]
            technique = f"{mapping['technique_id']} {mapping['technique']}"
            coverage[tactic]["techniques"].add(technique)
            coverage[tactic]["alert_count"] += 1

    return [
        {
            "tactic": tactic,
            "techniques": ", ".join(sorted(values["techniques"])),
            "alert_count": values["alert_count"],
        }
        for tactic, values in sorted(coverage.items())
    ]


def threat_intel_rows(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        for match in alert.get("threat_intel_context", []):
            rows.append(
                {
                    "alert_id": alert["alert_id"],
                    "indicator": match["indicator"],
                    "type": match["type"],
                    "threat_type": match["threat_type"],
                    "confidence": match["confidence"],
                    "source": match["source"],
                    "alert_title": alert["title"],
                }
            )
    return rows


def alert_table_rows(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        rows.append(
            {
                "alert_id": alert["alert_id"],
                "severity": alert["severity"],
                "risk_score": alert["risk_score"],
                "timestamp": alert["timestamp"],
                "rule": alert["matched_rule_title"],
                "user": alert["affected_user"],
                "account": alert["affected_account"],
                "source_ip": alert["source_ip"],
                "region": alert["aws_region"],
                "event": alert["event_name"],
                "threat_intel_match": bool(alert.get("threat_intel_context")),
                "mitre_tactics": ", ".join(sorted({item["tactic"] for item in alert.get("mitre_attack", [])})),
            }
        )
    return rows


def filter_alerts(
    alerts: list[dict[str, Any]],
    severities: list[str],
    rules: list[str],
    users: list[str],
    accounts: list[str],
    regions: list[str],
    threat_intel_only: bool,
) -> list[dict[str, Any]]:
    filtered = alerts
    if severities:
        filtered = [alert for alert in filtered if alert["severity"] in severities]
    if rules:
        filtered = [alert for alert in filtered if alert["matched_rule_title"] in rules]
    if users:
        filtered = [alert for alert in filtered if alert["affected_user"] in users]
    if accounts:
        filtered = [alert for alert in filtered if alert["affected_account"] in accounts]
    if regions:
        filtered = [alert for alert in filtered if alert["aws_region"] in regions]
    if threat_intel_only:
        filtered = [alert for alert in filtered if alert.get("threat_intel_context")]
    return filtered


def main() -> None:
    st.set_page_config(page_title="Cloud Detection Dashboard", layout="wide")
    st.title("Threat-Driven Cloud Detection Dashboard")

    with st.sidebar:
        log_set_name = st.radio("Log set", list(LOG_SETS), index=0)
        st.caption("Offline synthetic CloudTrail-style samples")

    alerts = run_detection_pipeline(LOG_SETS[log_set_name])
    report_markdown = render_report(alerts)

    _render_metrics(alerts)
    st.divider()

    if not alerts:
        st.info("No alerts were generated for the selected sample.")
        st.download_button("Download report", report_markdown, file_name="cloud_detection_report.md")
        return

    _render_severity_chart(alerts)
    st.divider()

    filtered_alerts = _render_filters(alerts)
    _render_alert_table(filtered_alerts)
    _render_alert_details(filtered_alerts)

    st.divider()
    _render_mitre_and_threat_intel(alerts)

    st.divider()
    st.subheader("Analyst Report")
    st.markdown(report_markdown)
    col_report, col_alerts = st.columns(2)
    with col_report:
        st.download_button("Download report", report_markdown, file_name="cloud_detection_report.md")
    with col_alerts:
        st.download_button(
            "Download alerts JSON",
            json.dumps(alerts, indent=2),
            file_name="alerts.json",
            mime="application/json",
        )


def _render_metrics(alerts: list[dict[str, Any]]) -> None:
    counts = severity_counts(alerts)
    affected_users = {alert["affected_user"] for alert in alerts if alert.get("affected_user")}
    tactics = {mapping["tactic"] for alert in alerts for mapping in alert.get("mitre_attack", [])}

    total_col, critical_high_col, ti_col, users_col, mitre_col = st.columns(5)
    total_col.metric("Total alerts", len(alerts))
    critical_high_col.metric("Critical / High", counts["critical"] + counts["high"])
    ti_col.metric("Threat-intel matches", threat_intel_match_count(alerts))
    users_col.metric("Affected users", len(affected_users))
    mitre_col.metric("MITRE tactics", len(tactics))


def _render_severity_chart(alerts: list[dict[str, Any]]) -> None:
    st.subheader("Severity Distribution")
    counts = severity_counts(alerts)
    chart_df = pd.DataFrame(
        [{"severity": severity, "alerts": count} for severity, count in counts.items() if count > 0]
    ).set_index("severity")
    if chart_df.empty:
        st.info("No severity data to display.")
        return
    st.bar_chart(chart_df)


def _render_filters(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    st.subheader("Alerts")
    filter_col_1, filter_col_2, filter_col_3 = st.columns(3)
    filter_col_4, filter_col_5, filter_col_6 = st.columns(3)

    severities = filter_col_1.multiselect("Severity", SEVERITY_ORDER)
    rules = filter_col_2.multiselect("Rule", sorted({alert["matched_rule_title"] for alert in alerts}))
    users = filter_col_3.multiselect("User", sorted({alert["affected_user"] for alert in alerts}))
    accounts = filter_col_4.multiselect("Account", sorted({alert["affected_account"] for alert in alerts}))
    regions = filter_col_5.multiselect("Region", sorted({alert["aws_region"] for alert in alerts}))
    threat_intel_only = filter_col_6.checkbox("Threat-intel matches only")

    return filter_alerts(alerts, severities, rules, users, accounts, regions, threat_intel_only)


def _render_alert_table(alerts: list[dict[str, Any]]) -> None:
    table_df = pd.DataFrame(alert_table_rows(alerts))
    if table_df.empty:
        st.info("No alerts match the selected filters.")
        return
    st.dataframe(table_df, use_container_width=True, hide_index=True)


def _render_alert_details(alerts: list[dict[str, Any]]) -> None:
    st.subheader("Alert Details")
    if not alerts:
        return

    for alert in sorted(alerts, key=lambda item: item["risk_score"], reverse=True):
        label = f"{alert['severity'].upper()} | {alert['risk_score']} | {alert['matched_rule_title']} | {alert['affected_user']}"
        with st.expander(label):
            detail_col_1, detail_col_2 = st.columns(2)
            with detail_col_1:
                st.write(
                    {
                        "alert_id": alert["alert_id"],
                        "timestamp": alert["timestamp"],
                        "account": alert["affected_account"],
                        "user": alert["affected_user"],
                        "source_ip": alert["source_ip"],
                        "region": alert["aws_region"],
                        "event": alert["event_name"],
                    }
                )
            with detail_col_2:
                st.write(
                    {
                        "recommended_action": alert["recommended_action"],
                        "false_positive_notes": alert["false_positive_notes"],
                    }
                )

            st.markdown("**MITRE ATT&CK**")
            st.dataframe(pd.DataFrame(alert["mitre_attack"]), use_container_width=True, hide_index=True)

            if alert.get("threat_intel_context"):
                st.markdown("**Threat Intelligence Context**")
                st.dataframe(pd.DataFrame(alert["threat_intel_context"]), use_container_width=True, hide_index=True)

            st.markdown("**Raw Event Snippet**")
            st.json(alert["raw_event"])


def _render_mitre_and_threat_intel(alerts: list[dict[str, Any]]) -> None:
    mitre_col, ti_col = st.columns(2)
    with mitre_col:
        st.subheader("MITRE ATT&CK Coverage")
        mitre_df = pd.DataFrame(mitre_coverage_rows(alerts))
        if mitre_df.empty:
            st.info("No MITRE mappings are available.")
        else:
            st.dataframe(mitre_df, use_container_width=True, hide_index=True)

    with ti_col:
        st.subheader("Threat Intelligence Matches")
        ti_df = pd.DataFrame(threat_intel_rows(alerts))
        if ti_df.empty:
            st.info("No threat-intelligence matches are available.")
        else:
            st.dataframe(ti_df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
