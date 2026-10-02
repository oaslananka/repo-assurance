from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import SchemaValidationError, validate_document


class BaselineEvidenceError(ValueError):
    """Raised when supplied current-baseline evidence is malformed or invalid."""


_AUTHORITY_RANK = {
    "secondary": 1,
    "upstream": 2,
    "official": 3,
}


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def create_baseline_request(
    *,
    subject: str,
    identifier: str,
    claim: str,
    reason: str,
    required_authority: str = "official",
) -> dict[str, str]:
    if required_authority not in _AUTHORITY_RANK:
        raise ValueError(f"unsupported authority requirement: {required_authority}")
    return {
        "type": "baseline_request",
        "subject": subject,
        "identifier": identifier,
        "claim": claim,
        "required_authority": required_authority,
        "reason": reason,
    }


def load_baseline_evidence(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineEvidenceError(f"unable to load baseline evidence: {exc}") from exc

    if isinstance(payload, dict):
        items = [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        raise BaselineEvidenceError("baseline evidence must be an object or list")

    validated: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise BaselineEvidenceError(f"baseline evidence item {index} is not an object")
        try:
            validate_document("baseline-evidence.v1", item)
        except SchemaValidationError as exc:
            raise BaselineEvidenceError(f"invalid baseline evidence item {index}: {exc}") from exc
        validated.append(item)
    return validated


def _authority_satisfies(actual: str, required: str) -> bool:
    return _AUTHORITY_RANK.get(actual, 0) >= _AUTHORITY_RANK.get(required, 999)


def match_baseline_request(
    request: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    *,
    as_of: datetime,
    max_age_days: int,
) -> Mapping[str, Any] | None:
    """Return the newest fresh authoritative evidence matching a baseline request."""
    if max_age_days < 0:
        raise ValueError("max_age_days must be non-negative")
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware")

    subject = str(request.get("subject", ""))
    claim = str(request.get("claim", ""))
    required_authority = str(request.get("required_authority", "official"))
    if required_authority not in _AUTHORITY_RANK:
        raise ValueError(f"unsupported authority requirement: {required_authority}")

    as_of_utc = as_of.astimezone(timezone.utc)
    max_age = timedelta(days=max_age_days)
    matches: list[tuple[datetime, Mapping[str, Any]]] = []

    for item in evidence:
        if str(item.get("subject", "")) != subject:
            continue
        if str(item.get("claim", "")) != claim:
            continue
        source = item.get("source")
        if not isinstance(source, Mapping):
            continue
        authority = str(source.get("authority", ""))
        if not _authority_satisfies(authority, required_authority):
            continue
        checked_at = _parse_time(item.get("checked_at"))
        if checked_at is None:
            continue
        if checked_at > as_of_utc:
            continue
        if as_of_utc - checked_at > max_age:
            continue
        matches.append((checked_at, item))

    if not matches:
        return None
    matches.sort(key=lambda pair: pair[0], reverse=True)
    return matches[0][1]
