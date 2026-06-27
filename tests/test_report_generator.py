from src.detection_engine import DetectionEngine
from src.log_loader import load_cloudtrail_logs
from src.report_generator import generate_markdown_report, render_report
from src.rule_loader import load_rules
from src.threat_intel import load_threat_intel


def test_report_generation_contains_expected_sections(tmp_path) -> None:
    alerts = DetectionEngine(load_rules("rules"), load_threat_intel("data/threat_intel")).run(
        load_cloudtrail_logs("data/logs/cloudtrail_suspicious.json")
    )
    report_path = tmp_path / "report.md"

    content = generate_markdown_report(alerts, report_path)

    assert report_path.exists()
    assert "Executive Summary" in content
    assert "MITRE ATT&CK Coverage" in content
    assert "Threat Intelligence Matches" in content


def test_empty_report_is_supported() -> None:
    content = render_report([])

    assert "Total alerts: 0" in content
    assert "No suspicious cloud activity" in content

