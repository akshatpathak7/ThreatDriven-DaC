from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_cloudtrail_logs(path: str | Path) -> list[dict[str, Any]]:
    """Load CloudTrail-style JSON logs from a list or {"Records": [...]} object."""
    log_path = Path(path)
    with log_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        records = payload["Records"]
    else:
        raise ValueError(f"{log_path} must contain a JSON list or a CloudTrail Records object")

    if not all(isinstance(record, dict) for record in records):
        raise ValueError(f"{log_path} contains non-object log records")
    return records


def load_many(paths: list[str | Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        records.extend(load_cloudtrail_logs(path))
    return records

