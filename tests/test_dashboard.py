from src.dashboard import alert_table_rows, mitre_coverage_rows, severity_counts, threat_intel_match_count
from src.pipeline import run_detection_pipeline


def test_dashboard_severity_counts() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    counts = severity_counts(alerts)

    assert counts["critical"] == 10
    assert counts["high"] == 2
    assert counts["medium"] == 0
    assert counts["low"] == 0


def test_dashboard_threat_intel_match_count() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    assert threat_intel_match_count(alerts) == 4


def test_dashboard_mitre_coverage_rows() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    rows = mitre_coverage_rows(alerts)

    assert any(row["tactic"] == "Initial Access" and row["alert_count"] == 6 for row in rows)
    assert any("T1562.008 Disable or Modify Cloud Logs" in row["techniques"] for row in rows)


def test_dashboard_alert_table_rows_include_filter_columns() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    rows = alert_table_rows(alerts)

    assert rows
    assert {
        "alert_id",
        "severity",
        "risk_score",
        "rule",
        "user",
        "source_ip",
        "region",
        "threat_intel_match",
        "mitre_tactics",
    }.issubset(rows[0])
