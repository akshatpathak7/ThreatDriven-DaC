from src.detection_engine import DetectionEngine
from src.log_loader import load_cloudtrail_logs
from src.rule_loader import load_rules
from src.threat_intel import load_threat_intel


def _engine() -> DetectionEngine:
    return DetectionEngine(load_rules("rules"), load_threat_intel("data/threat_intel"))


def test_detection_engine_matches_expected_suspicious_rules() -> None:
    alerts = _engine().run(load_cloudtrail_logs("data/logs/cloudtrail_suspicious.json"))
    matched_ids = {alert["matched_rule_id"] for alert in alerts}

    assert {
        "AWS-001",
        "AWS-002",
        "AWS-003",
        "AWS-004",
        "AWS-005",
        "AWS-006",
        "AWS-007",
        "AWS-008",
        "AWS-009",
        "AWS-010",
    }.issubset(matched_ids)


def test_detection_engine_does_not_alert_on_benign_logs() -> None:
    alerts = _engine().run(load_cloudtrail_logs("data/logs/cloudtrail_benign.json"))

    assert alerts == []


def test_malicious_ip_rule_includes_threat_intel_context() -> None:
    alerts = _engine().run(load_cloudtrail_logs("data/logs/cloudtrail_suspicious.json"))
    malicious_ip_alerts = [alert for alert in alerts if alert["matched_rule_id"] == "AWS-009"]

    assert malicious_ip_alerts
    assert malicious_ip_alerts[0]["threat_intel_context"][0]["indicator"] in {"203.0.113.66", "192.0.2.44"}

