from __future__ import annotations

import argparse
from pathlib import Path

from src.alert_generator import write_alerts_json
from src.detection_engine import DetectionEngine
from src.log_loader import load_many
from src.report_generator import generate_markdown_report
from src.rule_loader import load_rules
from src.threat_intel import load_threat_intel


def run_detection_pipeline(
    log_paths: list[str | Path],
    rules_dir: str | Path = "rules",
    threat_intel_dir: str | Path = "data/threat_intel",
) -> list[dict]:
    """Run detection and enrichment without writing output files."""
    rules = load_rules(rules_dir)
    events = load_many([Path(path) for path in log_paths])
    threat_intel = load_threat_intel(threat_intel_dir)
    return DetectionEngine(rules, threat_intel).run(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the cloud Detection-as-Code pipeline.")
    parser.add_argument(
        "--logs",
        nargs="+",
        default=["data/logs/cloudtrail_suspicious.json"],
        help="CloudTrail-style JSON log files to analyze.",
    )
    parser.add_argument("--rules", default="rules", help="Directory containing YAML detection rules.")
    parser.add_argument("--threat-intel", default="data/threat_intel", help="Directory containing offline IOC files.")
    parser.add_argument("--alerts-out", default="reports/alerts.json", help="Path for JSON alert output.")
    parser.add_argument(
        "--report-out", default="reports/sample_detection_report.md", help="Path for Markdown report output."
    )
    args = parser.parse_args()

    events = load_many([Path(path) for path in args.logs])
    rules = load_rules(args.rules)
    alerts = run_detection_pipeline(args.logs, args.rules, args.threat_intel)

    write_alerts_json(alerts, args.alerts_out)
    generate_markdown_report(alerts, args.report_out)

    print(f"Loaded {len(events)} log event(s), evaluated {len(rules)} rule(s), generated {len(alerts)} alert(s).")
    print(f"Alerts: {args.alerts_out}")
    print(f"Report: {args.report_out}")


if __name__ == "__main__":
    main()
