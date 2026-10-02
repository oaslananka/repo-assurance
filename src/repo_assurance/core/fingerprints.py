from __future__ import annotations

import re


_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "database-readiness",
        (
            re.compile(r"\bpg_isready\b", re.IGNORECASE),
            re.compile(r"postgres(?:ql)?\b.*\b(?:not ready|connection refused|no response|readiness)", re.IGNORECASE),
            re.compile(r"\b(?:database|db)\b.*\b(?:not ready|connection refused|readiness timeout)", re.IGNORECASE),
        ),
    ),
    (
        "registry-network",
        (
            re.compile(r"\b(?:ETIMEDOUT|ECONNRESET|ENETUNREACH|EAI_AGAIN)\b", re.IGNORECASE),
            re.compile(r"registry\.(?:npmjs\.org|yarnpkg\.com)", re.IGNORECASE),
            re.compile(r"\bregistry\b.*\b(?:timeout|network|connection|request failed)", re.IGNORECASE),
        ),
    ),
    (
        "permission-denied",
        (
            re.compile(r"\bpermission denied\b", re.IGNORECASE),
            re.compile(r"\bEACCES\b", re.IGNORECASE),
            re.compile(r"\boperation not permitted\b", re.IGNORECASE),
        ),
    ),
    (
        "snapshot-mismatch",
        (
            re.compile(r"\bsnapshot mismatch\b", re.IGNORECASE),
            re.compile(r"\bsnapshot\b.*\b(?:differs|different|failed|mismatch)\b", re.IGNORECASE),
        ),
    ),
    (
        "runner-unavailable",
        (
            re.compile(r"\bnot acquired by a runner\b", re.IGNORECASE),
            re.compile(r"\bno runner(?:s)? (?:available|online|matched)\b", re.IGNORECASE),
            re.compile(r"\brunner\b.*\b(?:unavailable|offline|timed? out waiting)\b", re.IGNORECASE),
        ),
    ),
)


def normalize_failure_fingerprint(
    *,
    job_name: str | None,
    step_name: str | None,
    message: str | None,
) -> str | None:
    """Map noisy CI failure text to a small stable root-signal category."""
    parts = [part for part in (job_name, step_name, message) if part]
    if not parts:
        return None

    haystack = "\n".join(parts)
    for fingerprint, patterns in _PATTERNS:
        if any(pattern.search(haystack) for pattern in patterns):
            return fingerprint
    return "unknown"
