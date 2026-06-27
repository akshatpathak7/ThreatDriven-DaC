from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IOC:
    value: str
    type: str
    threat_type: str
    confidence: int
    severity: str
    source: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    first_seen: str = ""
    last_seen: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.type.lower(), normalize_indicator(self.value, self.type))


def normalize_indicator(value: str, indicator_type: str) -> str:
    normalized = str(value).strip()
    if indicator_type.lower() in {"domain", "ip", "hash"}:
        normalized = normalized.lower()
    return normalized


class ThreatIntelStore:
    def __init__(self, indicators: list[IOC] | None = None) -> None:
        self._indicators: dict[tuple[str, str], IOC] = {}
        for indicator in indicators or []:
            self.add(indicator)

    def add(self, indicator: IOC) -> None:
        existing = self._indicators.get(indicator.key)
        if existing is None or indicator.confidence > existing.confidence:
            self._indicators[indicator.key] = indicator

    @property
    def indicators(self) -> list[IOC]:
        return list(self._indicators.values())

    def find(self, value: Any, indicator_type: str) -> IOC | None:
        if value is None:
            return None
        key = (indicator_type.lower(), normalize_indicator(str(value), indicator_type))
        return self._indicators.get(key)

    def enrich_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        source_ip = event.get("sourceIPAddress")
        ip_match = self.find(source_ip, "ip")
        if ip_match:
            matches.append(ioc_to_dict(ip_match))

        user_agent = str(event.get("userAgent", ""))
        for indicator in self.indicators:
            if indicator.type == "domain" and indicator.value.lower() in user_agent.lower():
                matches.append(ioc_to_dict(indicator))
        return matches


def ioc_to_dict(indicator: IOC) -> dict[str, Any]:
    return {
        "indicator": indicator.value,
        "type": indicator.type,
        "threat_type": indicator.threat_type,
        "confidence": indicator.confidence,
        "severity": indicator.severity,
        "source": indicator.source,
        "tags": list(indicator.tags),
        "first_seen": indicator.first_seen,
        "last_seen": indicator.last_seen,
    }


def load_threat_intel(directory: str | Path) -> ThreatIntelStore:
    intel_dir = Path(directory)
    store = ThreatIntelStore()

    for csv_path in (intel_dir / "malicious_ips.csv", intel_dir / "malicious_domains.csv"):
        if csv_path.exists():
            _load_csv(csv_path, store)

    stix_path = intel_dir / "sample_stix_indicators.json"
    if stix_path.exists():
        _load_stix(stix_path, store)

    return store


def _load_csv(path: Path, store: ThreatIntelStore) -> None:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            tags = tuple(tag.strip() for tag in row.get("tags", "").split("|") if tag.strip())
            store.add(
                IOC(
                    value=row["indicator"],
                    type=row["type"],
                    threat_type=row["threat_type"],
                    confidence=int(row["confidence"]),
                    severity=row["severity"],
                    source=row["source"],
                    tags=tags,
                    first_seen=row.get("first_seen", ""),
                    last_seen=row.get("last_seen", ""),
                )
            )


def _load_stix(path: Path, store: ThreatIntelStore) -> None:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    for item in payload.get("objects", []):
        if item.get("type") != "indicator":
            continue
        pattern = item.get("pattern", "")
        indicator_type, value = _parse_simple_stix_pattern(pattern)
        if not indicator_type or not value:
            continue
        labels = tuple(item.get("labels", []))
        store.add(
            IOC(
                value=value,
                type=indicator_type,
                threat_type=item.get("threat_type", labels[0] if labels else "unknown"),
                confidence=int(item.get("confidence", 50)),
                severity=item.get("severity", "medium"),
                source=item.get("created_by_ref", "sample-stix"),
                tags=labels,
                first_seen=item.get("valid_from", ""),
                last_seen=item.get("valid_until", ""),
            )
        )


def _parse_simple_stix_pattern(pattern: str) -> tuple[str | None, str | None]:
    mapping = {
        "ipv4-addr:value": "ip",
        "domain-name:value": "domain",
        "file:hashes.'SHA-256'": "hash",
    }
    for stix_field, indicator_type in mapping.items():
        token = f"{stix_field} = '"
        if token in pattern:
            value = pattern.split(token, 1)[1].split("'", 1)[0]
            return indicator_type, value
    return None, None

