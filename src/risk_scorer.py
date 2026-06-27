from __future__ import annotations

from typing import Any


SEVERITY_TO_SCORE = {"low": 20, "medium": 45, "high": 70, "critical": 90}
SCORE_TO_SEVERITY = [(80, "critical"), (60, "high"), (40, "medium"), (0, "low")]
SENSITIVE_EVENTS = {
    "AttachUserPolicy",
    "CreateAccessKey",
    "CreateUser",
    "DeleteTrail",
    "PutBucketPolicy",
    "StopLogging",
    "AuthorizeSecurityGroupIngress",
    "UpdateAccessKey",
}


def score_alert(rule: dict[str, Any], event: dict[str, Any], threat_matches: list[dict[str, Any]]) -> tuple[int, str]:
    score = max(int(rule["risk_score"]), SEVERITY_TO_SCORE[rule["severity"]])
    user_identity = event.get("userIdentity", {})

    if user_identity.get("type") == "Root":
        score += 12
    if _looks_admin(user_identity):
        score += 8
    if event.get("eventName") in SENSITIVE_EVENTS:
        score += 10
    if _mfa_absent(event):
        score += 10
    if threat_matches:
        score += 15
        score += max(match.get("confidence", 0) for match in threat_matches) // 10

    score = min(score, 100)
    return score, severity_from_score(score)


def severity_from_score(score: int) -> str:
    for minimum, severity in SCORE_TO_SEVERITY:
        if score >= minimum:
            return severity
    return "low"


def _looks_admin(user_identity: dict[str, Any]) -> bool:
    name = str(user_identity.get("userName", "")).lower()
    arn = str(user_identity.get("arn", "")).lower()
    return "admin" in name or "admin" in arn


def _mfa_absent(event: dict[str, Any]) -> bool:
    mfa_used = event.get("additionalEventData", {}).get("MFAUsed")
    return str(mfa_used).lower() in {"no", "false", "0"}

