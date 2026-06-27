from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from src.pipeline import run_detection_pipeline
from src.report_generator import render_report


LOG_SETS = {
    "suspicious": ["data/logs/cloudtrail_suspicious.json"],
    "benign": ["data/logs/cloudtrail_benign.json"],
    "both": ["data/logs/cloudtrail_benign.json", "data/logs/cloudtrail_suspicious.json"],
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def analyze(logs: str) -> dict[str, Any]:
    alerts = run_detection_pipeline(LOG_SETS[logs])
    return {
        "ok": True,
        "alerts": alerts,
        "summary": summarize_alerts(alerts),
        "report_markdown": render_report(alerts),
        "error": None,
    }


def report(logs: str) -> dict[str, Any]:
    alerts = run_detection_pipeline(LOG_SETS[logs])
    return {
        "ok": True,
        "alerts": [],
        "summary": summarize_alerts(alerts),
        "report_markdown": render_report(alerts),
        "error": None,
    }


def run_tests(pytest_args: list[str] | None = None) -> dict[str, Any]:
    args = pytest_args or ["-q"]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *args],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    return {
        "ok": result.returncode == 0,
        "exit_code": result.returncode,
        "output": output,
        "error": None if result.returncode == 0 else "pytest failed",
    }


def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter(alert["severity"] for alert in alerts)
    affected_users = sorted({alert["affected_user"] for alert in alerts if alert.get("affected_user")})
    affected_accounts = sorted({alert["affected_account"] for alert in alerts if alert.get("affected_account")})
    tactics = sorted(
        {mapping["tactic"] for alert in alerts for mapping in alert.get("mitre_attack", []) if mapping.get("tactic")}
    )
    threat_intel_matches = sum(1 for alert in alerts if alert.get("threat_intel_context"))

    return {
        "total_alerts": len(alerts),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
        "critical_high": severity_counts.get("critical", 0) + severity_counts.get("high", 0),
        "threat_intel_matches": threat_intel_matches,
        "affected_users": affected_users,
        "affected_accounts": affected_accounts,
        "mitre_tactics": tactics,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="JSON bridge for the ThreatDriven-DaC macOS app.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Run detections and return alerts.")
    analyze_parser.add_argument("--logs", choices=sorted(LOG_SETS), default="suspicious")

    report_parser = subparsers.add_parser("report", help="Render the analyst report.")
    report_parser.add_argument("--logs", choices=sorted(LOG_SETS), default="suspicious")

    test_parser = subparsers.add_parser("test", help="Run pytest and return captured output.")
    test_parser.add_argument("--pytest-args", nargs=argparse.REMAINDER, default=None)

    args = parser.parse_args()

    try:
        if args.command == "analyze":
            response = analyze(args.logs)
        elif args.command == "report":
            response = report(args.logs)
        else:
            response = run_tests(args.pytest_args)
    except Exception as exc:  # Keep stdout JSON-only for the Swift app.
        response = {
            "ok": False,
            "alerts": [],
            "summary": {},
            "report_markdown": "",
            "exit_code": 1,
            "output": "",
            "error": str(exc),
        }

    print(json.dumps(response))


if __name__ == "__main__":
    main()
