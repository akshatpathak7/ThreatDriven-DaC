from src.detection_engine import DetectionEngine
from src.log_loader import load_cloudtrail_logs
from src.rule_loader import load_rules
from src.threat_intel import load_threat_intel


def test_alert_structure_contains_required_fields() -> None:
    alerts = DetectionEngine(load_rules("rules"), load_threat_intel("data/threat_intel")).run(
        load_cloudtrail_logs("data/logs/cloudtrail_suspicious.json")
    )
    required = {
        "alert_id",
        "title",
        "severity",
        "risk_score",
        "timestamp",
        "affected_account",
        "affected_user",
        "source_ip",
        "aws_region",
        "event_name",
        "matched_rule_id",
        "matched_rule_title",
        "threat_intel_context",
        "mitre_attack",
        "recommended_action",
        "false_positive_notes",
    }

    assert alerts
    assert required.issubset(alerts[0])
    assert alerts[0]["alert_id"].startswith("ALT-")

