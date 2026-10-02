from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from repo_assurance.collectors.baseline import (
    BaselineEvidenceError,
    create_baseline_request,
    load_baseline_evidence,
    match_baseline_request,
)

AS_OF = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def baseline(*, subject: str, status: str = "current", authority: str = "official", checked_at: str = "2026-10-02T08:00:00Z", claim: str = "runner lifecycle") -> dict:
    return {
        "schema_version": "baseline-evidence/v1",
        "subject": subject,
        "claim": claim,
        "status": status,
        "effective_dates": {},
        "source": {
            "authority": authority,
            "publisher": "GitHub",
            "url": "https://docs.github.com/example",
        },
        "checked_at": checked_at,
    }


def test_create_baseline_request_is_explicit_about_authority() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="runner lifecycle is time-sensitive",
    )

    assert request == {
        "type": "baseline_request",
        "subject": "github-actions/macos-14",
        "identifier": "macos-14",
        "claim": "runner lifecycle",
        "required_authority": "official",
        "reason": "runner lifecycle is time-sensitive",
    }


def test_load_baseline_evidence_accepts_list_and_validates_schema(tmp_path: Path) -> None:
    path = tmp_path / "baselines.json"
    path.write_text(json.dumps([
        baseline(subject="github-actions/ubuntu-latest"),
        baseline(subject="github-actions/macos-14", status="retiring"),
    ]), encoding="utf-8")

    loaded = load_baseline_evidence(path)

    assert [item["subject"] for item in loaded] == [
        "github-actions/ubuntu-latest",
        "github-actions/macos-14",
    ]


def test_invalid_baseline_document_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    item = baseline(subject="github-actions/ubuntu-latest")
    item["schema_version"] = "baseline-evidence/v2"
    path.write_text(json.dumps(item), encoding="utf-8")

    with pytest.raises(BaselineEvidenceError):
        load_baseline_evidence(path)


def test_current_official_evidence_matches_request() -> None:
    request = create_baseline_request(
        subject="github-actions/ubuntu-latest",
        identifier="ubuntu-latest",
        claim="runner lifecycle",
        reason="time-sensitive",
    )

    matched = match_baseline_request(
        request,
        [baseline(subject="github-actions/ubuntu-latest")],
        as_of=AS_OF,
        max_age_days=1,
    )

    assert matched is not None
    assert matched["status"] == "current"


def test_retiring_runner_status_is_preserved_for_evaluator() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="time-sensitive",
    )
    item = baseline(subject="github-actions/macos-14", status="retiring")
    item["effective_dates"] = {"retirement": "2026-11-02"}

    matched = match_baseline_request(
        request, [item], as_of=AS_OF, max_age_days=1
    )

    assert matched is not None
    assert matched["status"] == "retiring"
    assert matched["effective_dates"]["retirement"] == "2026-11-02"


def test_secondary_source_does_not_satisfy_official_requirement() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="time-sensitive",
    )

    assert match_baseline_request(
        request,
        [baseline(subject="github-actions/macos-14", authority="secondary")],
        as_of=AS_OF,
        max_age_days=1,
    ) is None


def test_stale_baseline_does_not_match_current_request() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="time-sensitive",
    )

    assert match_baseline_request(
        request,
        [baseline(subject="github-actions/macos-14", checked_at="2026-09-20T00:00:00Z")],
        as_of=AS_OF,
        max_age_days=1,
    ) is None


def test_latest_matching_evidence_wins_deterministically() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="time-sensitive",
    )
    older = baseline(subject="github-actions/macos-14", status="current", checked_at="2026-10-02T07:00:00Z")
    newer = baseline(subject="github-actions/macos-14", status="retiring", checked_at="2026-10-02T09:00:00Z")

    matched = match_baseline_request(
        request, [newer, older], as_of=AS_OF, max_age_days=1
    )

    assert matched is newer


def test_missing_current_evidence_returns_none_instead_of_model_fallback() -> None:
    request = create_baseline_request(
        subject="github-actions/macos-14",
        identifier="macos-14",
        claim="runner lifecycle",
        reason="time-sensitive",
    )

    assert match_baseline_request(request, [], as_of=AS_OF, max_age_days=1) is None
