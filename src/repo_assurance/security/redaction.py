from __future__ import annotations

import copy
import json
import re
from typing import Any


class SensitiveDataError(ValueError):
    """Raised when secret-like material remains in a canonical document."""


_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
}
_BENIGN_KEYS = {"token_count", "secret_type"}
_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS and normalized not in _BENIGN_KEYS


def _redact_string(value: str) -> tuple[str, bool]:
    changed = False
    result = value
    for pattern in _PATTERNS:
        next_value, count = pattern.subn(_REDACTED, result)
        if count:
            changed = True
            result = next_value
    return result, changed


def sanitize_evidence(document: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied evidence document with secret-like values removed."""
    result = copy.deepcopy(document)
    redactions = list(result.get("redactions", []))

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                if key == "redactions":
                    sanitized[key] = child
                elif _is_sensitive_key(key) and child not in (None, ""):
                    sanitized[key] = _REDACTED
                    redactions.append({"kind": "credential", "field": child_path, "method": "removed"})
                else:
                    sanitized[key] = walk(child, child_path)
            return sanitized
        if isinstance(value, list):
            return [walk(item, f"{path}[{index}]") for index, item in enumerate(value)]
        if isinstance(value, str):
            sanitized, changed = _redact_string(value)
            if changed:
                redactions.append({"kind": "credential", "field": path, "method": "masked"})
            return sanitized
        return value

    result = walk(result, "")
    result["redactions"] = redactions
    return result


def assert_no_secret_values(document: object) -> None:
    """Fail if canonical data still contains obvious secret-like material."""
    def inspect(value: Any, key: str | None = None) -> None:
        if key is not None and _is_sensitive_key(key) and value not in (None, "", _REDACTED):
            raise SensitiveDataError(f"sensitive field is not redacted: {key}")
        if isinstance(value, dict):
            for child_key, child in value.items():
                inspect(child, child_key)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
        elif isinstance(value, str):
            for pattern in _PATTERNS:
                if pattern.search(value):
                    raise SensitiveDataError("secret-like value remains in canonical document")

    inspect(document)
    json.dumps(document)
