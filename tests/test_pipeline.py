from src.pipeline import run_detection_pipeline


def test_run_detection_pipeline_suspicious_logs_trigger_alerts() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_suspicious.json"])

    assert len(alerts) == 12
    assert {alert["matched_rule_id"] for alert in alerts}.issuperset({"AWS-001", "AWS-009"})


def test_run_detection_pipeline_benign_logs_do_not_alert() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_benign.json"])

    assert alerts == []


def test_run_detection_pipeline_combined_logs_include_suspicious_detections() -> None:
    alerts = run_detection_pipeline(["data/logs/cloudtrail_benign.json", "data/logs/cloudtrail_suspicious.json"])

    assert len(alerts) == 12
    assert any(alert["matched_rule_title"] == "CloudTrail Logging Stopped or Deleted" for alert in alerts)

