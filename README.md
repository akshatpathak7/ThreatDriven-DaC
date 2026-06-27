# Threat-Driven Detection-as-Code Cloud Security Pipeline

A defensive, educational cloud security project that analyzes synthetic AWS CloudTrail-style logs with YAML detection rules, enriches suspicious activity with offline threat intelligence, maps alerts to MITRE ATT&CK Cloud techniques, and validates detection logic through pytest and GitHub Actions.

This project is designed to feel like a lightweight SOC and cloud detection engineering workflow that is easy to explain in interviews.

Project note: this repository is maintained as a practical detection-engineering portfolio demo.

## Why This Project Matters

Modern cloud security teams need repeatable detection engineering practices: version-controlled rules, realistic test data, structured alerts, threat-intelligence context, and automated validation before rules are merged. This project demonstrates those skills without relying on paid APIs or unsafe offensive code.

All logs and indicators are synthetic samples. The project is defensive only and does not contain exploitation, credential theft, malware, persistence code, or harmful automation.

## Architecture

```text
CloudTrail-style JSON logs
        |
        v
YAML detection rules  --->  Rule schema validation
        |
        v
Python detection engine
        |
        v
Offline threat-intelligence enrichment
        |
        v
Risk scoring + MITRE ATT&CK Cloud mapping
        |
        v
JSON alerts + Markdown analyst report
        |
        +--> Streamlit SOC-style dashboard
        |
        v
pytest + GitHub Actions Detection-as-Code validation
```

## Features

- Loads AWS CloudTrail-style JSON logs from `Records` objects or JSON lists.
- Uses YAML rules for Detection-as-Code.
- Supports nested field matching, equality, contains, list matching, negative list matching, IOC matching, and basic threshold-style rule logic.
- Includes 10 cloud security detections:
  - Root account console login
  - Console login without MFA
  - IAM user creation
  - AdministratorAccess policy attached to user
  - New access key created
  - Public S3 bucket policy
  - CloudTrail logging stopped or deleted
  - Security group opened to `0.0.0.0/0`
  - API activity from a known malicious IP
  - Activity from an unusual AWS region
- Enriches alerts with mock CSV and STIX-style threat intelligence.
- Calculates final risk using rule severity, IOC confidence, root/admin context, sensitive action type, malicious source IP, and missing MFA.
- Maps detections to MITRE ATT&CK Cloud tactics and techniques.
- Generates structured JSON alerts and a Markdown analyst report.
- Provides a local Streamlit dashboard for reviewing alerts, risk, MITRE coverage, and threat-intelligence matches.
- Includes a native SwiftUI macOS app for running detections, tests, and viewing results locally.
- Includes pytest coverage and GitHub Actions CI validation.

## Folder Structure

```text
.
├── README.md
├── requirements.txt
├── pyproject.toml
├── data/
│   ├── logs/
│   │   ├── cloudtrail_benign.json
│   │   └── cloudtrail_suspicious.json
│   └── threat_intel/
│       ├── malicious_ips.csv
│       ├── malicious_domains.csv
│       └── sample_stix_indicators.json
├── rules/
│   ├── root_console_login.yml
│   ├── console_login_without_mfa.yml
│   ├── iam_user_created.yml
│   ├── admin_policy_attached.yml
│   ├── access_key_created.yml
│   ├── public_s3_bucket_policy.yml
│   ├── cloudtrail_stopped.yml
│   ├── security_group_open_to_world.yml
│   ├── malicious_ip_api_call.yml
│   └── unusual_region_activity.yml
├── src/
│   ├── __init__.py
│   ├── log_loader.py
│   ├── rule_loader.py
│   ├── detection_engine.py
│   ├── threat_intel.py
│   ├── risk_scorer.py
│   ├── alert_generator.py
│   ├── report_generator.py
│   ├── ai_summary.py
│   ├── dashboard.py
│   └── pipeline.py
├── tests/
├── macos/
│   └── ThreatDrivenDaC/
├── scripts/
│   └── build_macos_app.sh
├── reports/
│   ├── alerts.json
│   └── sample_detection_report.md
└── .github/workflows/detection-tests.yml
```

## Setup

Use Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## Run the Dashboard

Start the local Streamlit dashboard:

```bash
streamlit run src/dashboard.py
```

The dashboard shows:

- Alert summary metrics for total alerts, critical/high alerts, threat-intelligence matches, affected users, and MITRE tactics.
- Severity distribution chart.
- Filterable alert table by severity, rule, user, account, region, and threat-intelligence match.
- Alert detail expanders with MITRE mapping, IOC context, recommended actions, false-positive notes, and raw event snippets.
- MITRE ATT&CK coverage and threat-intelligence match tables.
- Analyst report preview with downloadable Markdown and JSON outputs.

## Run the Native macOS App

The project includes a local unsigned SwiftUI app that uses the repository `.venv` Python runtime. It does not bundle Python, so install dependencies first:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Build the unsigned app bundle:

```bash
scripts/build_macos_app.sh
```

Open it:

```bash
open dist/ThreatDrivenDaC.app
```

The app can:

- run detections against suspicious, benign, or combined sample logs
- show native dashboard cards, severity distribution, alert table, MITRE coverage, and threat-intelligence context
- run `pytest` and display captured output
- render the analyst Markdown report as readable text

Because this is an unsigned local portfolio app, macOS may show a Gatekeeper warning if the app is moved or opened outside the development folder. For this demo workflow, build and open it from the repository root.

## Run the Pipeline

Analyze the suspicious sample logs:

```bash
python3 -m src.pipeline --logs data/logs/cloudtrail_suspicious.json
```

Analyze both benign and suspicious logs:

```bash
python3 -m src.pipeline \
  --logs data/logs/cloudtrail_benign.json data/logs/cloudtrail_suspicious.json \
  --alerts-out reports/alerts.json \
  --report-out reports/sample_detection_report.md
```

Expected sample output:

```text
Loaded 10 log event(s), evaluated 10 rule(s), generated 12 alert(s).
Alerts: reports/alerts.json
Report: reports/sample_detection_report.md
```

## Run Tests

```bash
python3 -m pytest -q
```

The tests validate rule schema, log loading, threat-intel loading, IOC matching, detection behavior, alert structure, and report generation.

## Example Detection Rule

```yaml
id: AWS-004
title: AdministratorAccess Policy Attached to User
description: Detects attachment of the AWS managed AdministratorAccess policy to an IAM user.
logsource:
  product: aws
  service: iam
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: AttachUserPolicy
    requestParameters.policyArn:
      contains: AdministratorAccess
  condition: selection
severity: critical
risk_score: 88
mitre_attack:
  - tactic: Privilege Escalation
    technique_id: T1098.003
    technique: Additional Cloud Roles
false_positive: Emergency access grants may attach AdministratorAccess temporarily, but should have explicit approval and expiry.
recommended_action: Remove unauthorized administrator access, inspect the principal that made the change, and review subsequent API activity.
```

## Example Alert Output

```json
{
  "alert_id": "ALT-32E4C1E321E9",
  "title": "Root Account Console Login",
  "severity": "critical",
  "risk_score": 100,
  "timestamp": "2026-06-11T01:00:00Z",
  "affected_account": "111122223333",
  "affected_user": "arn:aws:iam::111122223333:root",
  "source_ip": "203.0.113.66",
  "aws_region": "us-east-1",
  "event_name": "ConsoleLogin",
  "matched_rule_id": "AWS-001",
  "matched_rule_title": "Root Account Console Login",
  "threat_intel_context": [
    {
      "indicator": "203.0.113.66",
      "type": "ip",
      "threat_type": "credential_access_infrastructure",
      "confidence": 92,
      "severity": "critical",
      "source": "MockTI"
    }
  ],
  "mitre_attack": [
    {
      "tactic": "Initial Access",
      "technique_id": "T1078.004",
      "technique": "Cloud Accounts"
    }
  ],
  "recommended_action": "Verify the login owner, confirm MFA usage, rotate root credentials if unauthorized, and review account-level changes."
}
```

## Sample Report Excerpt

Generated report: `reports/sample_detection_report.md`

```text
Total alerts: 12
Critical: 10
High: 2
Threat intelligence matches: 4

Highest-risk activity:
Root Account Console Login affecting arn:aws:iam::111122223333:root from 203.0.113.66.
```

The report includes an executive summary, severity breakdown, high/critical alerts, threat-intelligence matches, MITRE ATT&CK coverage, affected users/accounts, recommended next steps, and false-positive considerations.

## Detection-as-Code CI/CD

GitHub Actions workflow: `.github/workflows/detection-tests.yml`

The workflow runs on every push and pull request:

```text
install dependencies -> validate YAML rules -> run pytest -> run sample pipeline
```

This makes rule changes testable and reviewable like application code.

## Skills Demonstrated

- Cloud security monitoring with AWS CloudTrail-style telemetry
- Detection engineering and Detection-as-Code
- Python automation and modular pipeline design
- YAML rule authoring and schema validation
- Offline threat-intelligence enrichment with CSV and STIX-style data
- MITRE ATT&CK Cloud mapping
- Risk scoring and analyst-ready alert generation
- Markdown report generation for SOC workflows
- Streamlit dashboarding for local SOC-style demos
- Native SwiftUI macOS app shell for portfolio demos
- pytest test coverage
- GitHub Actions CI/CD validation

## Resume Bullet

“Built a Python-based Threat-Driven Detection-as-Code Cloud Security Pipeline that analyzes AWS CloudTrail-style logs, detects risky IAM/S3/CloudTrail/security group events using YAML rules, enriches alerts with STIX-style threat intelligence, maps detections to MITRE ATT&CK Cloud techniques, and validates rules through GitHub Actions CI/CD tests.”

## Future Improvements

- Add Sigma-like rule conversion or export.
- Add richer threshold and sequence detections.
- Add allowlists for approved automation roles, regions, and CIDR ranges.
- Add HTML report output.
- Add optional LLM-based analyst summaries while keeping offline rule-based summaries as the default.
- Add code signing and notarization for a distributable macOS release.
