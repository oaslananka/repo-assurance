from __future__ import annotations

import pytest

from repo_assurance.core.schema import SchemaValidationError, validate_document


SUBJECT = {"type": "repository", "identifier": "oaslananka/repo-assurance"}


def assert_invalid(schema_name: str, document: object) -> None:
    with pytest.raises(SchemaValidationError):
        validate_document(schema_name, document)


def test_evidence_requires_subject() -> None:
    assert_invalid(
        "evidence.v1",
        {
            "schema_version": "evidence/v1",
            "id": "ev_1",
            "kind": "source",
            "source": {"provider": "git", "mechanism": "cli", "collector": "git/v1"},
            "observation": {},
            "snapshot": {"repository": "oaslananka/repo-assurance", "target_commit_sha": "a" * 40},
            "collected_at": "2026-10-02T00:00:00Z",
            "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        },
    )


def test_evidence_rejects_unknown_kind() -> None:
    document = valid_evidence()
    document["kind"] = "magic"
    assert_invalid("evidence.v1", document)


def test_finding_requires_evidence_ids() -> None:
    document = valid_finding()
    document.pop("evidence_ids")
    assert_invalid("finding.v1", document)


def test_finding_rejects_unknown_severity() -> None:
    document = valid_finding()
    document["severity"] = "URGENT"
    assert_invalid("finding.v1", document)


def test_control_rejects_empty_allowed_states() -> None:
    document = valid_control()
    document["outputs"]["allowed_states"] = []
    assert_invalid("control.v1", document)


def test_audit_plan_requires_controls() -> None:
    document = valid_audit_plan()
    document.pop("controls")
    assert_invalid("audit-plan.v1", document)


def test_unsupported_schema_major_version_rejected() -> None:
    document = valid_evidence()
    document["schema_version"] = "evidence/v2"
    assert_invalid("evidence.v1", document)


@pytest.mark.parametrize(
    ("schema_name", "document_factory"),
    [
        ("control.v1", lambda: valid_control()),
        ("control-result.v1", lambda: valid_control_result()),
        ("evidence.v1", lambda: valid_evidence()),
        ("audit-plan.v1", lambda: valid_audit_plan()),
        ("candidate-finding.v1", lambda: valid_candidate()),
        ("finding.v1", lambda: valid_finding()),
        ("baseline-evidence.v1", lambda: valid_baseline()),
        ("audit-report.v1", lambda: valid_report()),
    ],
)
def test_minimal_valid_documents_pass(schema_name: str, document_factory) -> None:
    validate_document(schema_name, document_factory())


def valid_control() -> dict:
    return {
        "schema_version": "control/v1",
        "id": "CI-OPS-003",
        "title": "Chronic workflow failure",
        "domain": "cicd",
        "description": "Detect persistent workflow failure.",
        "applicability": {"all_capabilities": ["github_actions"], "any_capabilities": [], "excluded_repository_types": []},
        "evidence_requirements": {"minimum_kinds": ["github_history"], "minimum_items": 1},
        "evaluation": {"time_sensitive": True, "correlation_required": False, "dynamic_execution": False},
        "outputs": {"allowed_states": ["PASS", "FINDING", "INCONCLUSIVE"]},
    }


def valid_control_result() -> dict:
    return {
        "schema_version": "control-result/v1",
        "control_id": "CI-OPS-003",
        "state": "PASS",
        "subject": SUBJECT,
        "evidence_ids": ["ev_1"],
        "candidate_finding_ids": [],
        "evaluated_at": "2026-10-02T00:00:00Z",
    }


def valid_evidence() -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_1",
        "kind": "source",
        "source": {"provider": "git", "mechanism": "cli", "collector": "git/v1"},
        "subject": SUBJECT,
        "observation": {},
        "snapshot": {"repository": "oaslananka/repo-assurance", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def valid_audit_plan() -> dict:
    return {
        "schema_version": "audit-plan/v1",
        "audit_id": "audit_1",
        "mode": "standard",
        "repository": {"owner": "oaslananka", "name": "repo-assurance", "full_name": "oaslananka/repo-assurance"},
        "snapshot": {"target_branch": "main", "target_commit_sha": "a" * 40},
        "capabilities": {"github": True},
        "controls": [{"control_id": "CI-OPS-003", "applicable": False, "reason": "missing_capability"}],
        "budgets": {"github": {"max_runs_per_workflow": 100, "max_history_days": 90}, "current_baseline": {"max_external_lookups": 20}},
    }


def valid_candidate() -> dict:
    return {
        "schema_version": "candidate-finding/v1",
        "candidate_id": "candidate_1",
        "control_id": "CI-OPS-003",
        "subject": SUBJECT,
        "type": "CHRONIC_FAILURE",
        "evidence_ids": ["ev_1"],
        "proposed_severity": "HIGH",
        "proposed_confidence": "CONFIRMED",
    }


def valid_finding() -> dict:
    return {
        "schema_version": "finding/v1",
        "id": "CICD-CHRONIC-deadbeef",
        "fingerprint": "sha256:" + "a" * 64,
        "control_ids": ["CI-OPS-003"],
        "title": "Required workflow is chronically failing",
        "domain": "cicd",
        "type": "UNRELIABLE_GATE",
        "output_class": "FINDING",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "priority": "P1",
        "lifecycle": "OPEN",
        "subject": SUBJECT,
        "observed": {"summary": "8 of 10 runs failed."},
        "expected": {"summary": "Required gate should be reliable."},
        "impact": {"summary": "Merge signal is unreliable."},
        "evidence_ids": ["ev_1"],
        "root_cause": {"state": "UNKNOWN", "summary": "Unknown."},
        "remediation": {"summary": "Investigate failures.", "effort": "M"},
        "verification": {"summary": "Observe repeated healthy runs."},
        "relationships": {"caused_by": [], "related_to": [], "duplicates": [], "blocked_by": [], "blocks": []},
    }


def valid_baseline() -> dict:
    return {
        "schema_version": "baseline-evidence/v1",
        "subject": "github-actions/ubuntu-latest",
        "claim": "runner lifecycle",
        "status": "current",
        "source": {"authority": "official", "publisher": "GitHub"},
        "checked_at": "2026-10-02T00:00:00Z",
    }


def valid_report() -> dict:
    return {
        "schema_version": "audit-report/v1",
        "audit": {"id": "audit_1", "mode": "standard", "started_at": "2026-10-02T00:00:00Z", "completed_at": "2026-10-02T00:01:00Z", "baseline_as_of": "2026-10-02"},
        "repository": {"full_name": "oaslananka/repo-assurance"},
        "snapshot": {"target_commit_sha": "a" * 40},
        "profile": {},
        "plan_summary": {"catalog_controls": 1, "applicable": 1, "not_applicable": 0},
        "coverage": {},
        "control_results": [],
        "providers": [],
        "findings": [],
        "observations": [],
        "blind_spots": [],
        "remediation_tracks": [],
    }
