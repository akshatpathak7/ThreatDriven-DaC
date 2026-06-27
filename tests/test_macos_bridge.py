from src.macos_bridge import analyze, report, run_tests, summarize_alerts
from src.pipeline import run_detection_pipeline


def test_macos_bridge_analyze_suspicious_returns_alerts_and_summary() -> None:
    response = analyze("suspicious")

    assert response["ok"] is True
    assert len(response["alerts"]) == 12
    assert response["summary"]["total_alerts"] == 12
    assert response["summary"]["severity_counts"]["critical"] == 10
    assert "Threat-Driven Cloud Detection Report" in response["report_markdown"]


def test_macos_bridge_analyze_benign_returns_no_alerts() -> None:
    response = analyze("benign")

    assert response["ok"] is True
    assert response["alerts"] == []
    assert response["summary"]["total_alerts"] == 0
    assert "No suspicious cloud activity" in response["report_markdown"]


def test_macos_bridge_report_returns_report_without_alert_payload() -> None:
    response = report("suspicious")

    assert response["ok"] is True
    assert response["alerts"] == []
    assert response["summary"]["total_alerts"] == 12
    assert "Threat Intelligence Matches" in response["report_markdown"]


def test_macos_bridge_test_command_returns_pytest_output() -> None:
    response = run_tests(["tests/test_log_loader.py", "-q"])

    assert response["ok"] is True
    assert response["exit_code"] == 0
    assert "passed" in response["output"]


def test_summarize_alerts_shape() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    summary = summarize_alerts(alerts)

    assert summary["critical_high"] == 12
    assert summary["threat_intel_matches"] == 4
    assert "Initial Access" in summary["mitre_tactics"]
