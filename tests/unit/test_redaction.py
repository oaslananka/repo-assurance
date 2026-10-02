from __future__ import annotations

import json

import pytest

from repo_assurance.security.redaction import (
    SensitiveDataError,
    assert_no_secret_values,
    sanitize_evidence,
)

FAKE_PAT = "ghp_" + "A" * 36
FAKE_BEARER = "Bearer very-secret-access-token-value"
FAKE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----"


def base_evidence() -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_secret",
        "kind": "source",
        "source": {"provider": "fixture", "mechanism": "test", "collector": "fixture/v1"},
        "subject": {"type": "file", "identifier": "config.txt"},
        "observation": {},
        "snapshot": {"repository": "owner/repo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def test_sanitize_redacts_sensitive_named_fields() -> None:
    evidence = base_evidence()
    evidence["observation"] = {
        "authorization": FAKE_BEARER,
        "password": "correct horse battery staple",
        "api_key": "fixture-api-key-value",
        "nested": {"credential": "fixture-credential-value"},
    }

    result = sanitize_evidence(evidence)
    serialized = json.dumps(result)

    assert FAKE_BEARER not in serialized
    assert "correct horse battery staple" not in serialized
    assert "fixture-api-key-value" not in serialized
    assert "fixture-credential-value" not in serialized
    assert result["observation"]["authorization"] == "[REDACTED]"
    assert result["redactions"]


def test_sanitize_redacts_secret_patterns_in_free_text() -> None:
    evidence = base_evidence()
    evidence["observation"] = {
        "log": f"token accidentally printed: {FAKE_PAT}\n{FAKE_PRIVATE_KEY}"
    }

    result = sanitize_evidence(evidence)
    serialized = json.dumps(result)

    assert FAKE_PAT not in serialized
    assert FAKE_PRIVATE_KEY not in serialized
    assert "[REDACTED]" in serialized


def test_sanitize_does_not_mutate_input() -> None:
    evidence = base_evidence()
    evidence["observation"] = {"password": "fixture-password"}

    sanitize_evidence(evidence)

    assert evidence["observation"]["password"] == "fixture-password"


def test_assert_no_secret_values_rejects_unsanitized_document() -> None:
    evidence = base_evidence()
    evidence["observation"] = {"message": f"leaked {FAKE_PAT}"}

    with pytest.raises(SensitiveDataError):
        assert_no_secret_values(evidence)


def test_assert_no_secret_values_accepts_sanitized_document() -> None:
    evidence = base_evidence()
    evidence["observation"] = {"authorization": FAKE_BEARER}

    result = sanitize_evidence(evidence)

    assert_no_secret_values(result)


def test_benign_metadata_is_not_redacted() -> None:
    evidence = base_evidence()
    evidence["observation"] = {"token_count": 123, "secret_type": "GitHub PAT"}

    result = sanitize_evidence(evidence)

    assert result["observation"] == {"token_count": 123, "secret_type": "GitHub PAT"}
