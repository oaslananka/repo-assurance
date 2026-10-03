from __future__ import annotations

import pytest

from repo_assurance.core.correlation import CorrelationError, correlate
from repo_assurance.core.schema import validate_document


SUBJECT = {"type": "github_workflow", "identifier": ".github/workflows/ci.yml"}


def evidence(evidence_id: str = "ev_1") -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "github_history",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": SUBJECT,
        "observation": {},
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def result(control_id: str, state: str = "FINDING", *, subject: dict | None = None, evidence_ids: list[str] | None = None, reason: str = "fixture") -> dict:
    return {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": subject or SUBJECT,
        "evidence_ids": evidence_ids if evidence_ids is not None else ["ev_1"],
        "candidate_finding_ids": [],
        "evaluated_at": "2026-10-02T00:00:00Z",
        "reason": reason,
    }


def test_required_unreliable_gate_becomes_candidate() -> None:
    candidates = correlate(
        control_results=[result("CI-OPS-006", reason="required_gate_unreliable:10")],
        evidence=[evidence()],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["type"] == "UNRELIABLE_GATE"
    assert candidate["proposed_severity"] == "HIGH"
    assert candidate["proposed_confidence"] == "CONFIRMED"
    validate_document("candidate-finding.v1", candidate)


def test_healthy_or_unknown_control_does_not_create_candidate() -> None:
    candidates = correlate(
        control_results=[
            result("CI-OPS-006", state="PASS"),
            result("GH-GOV-001", state="UNKNOWN_PERMISSION"),
        ],
        evidence=[evidence()],
    )

    assert candidates == []


def test_stale_control_and_enforcement_gap_have_distinct_types() -> None:
    candidates = correlate(
        control_results=[
            result("CI-OPS-008", reason="expected_workflow_has_no_observed_runs"),
            result("CI-OPS-007", reason="healthy_expected_gate_not_required:10"),
        ],
        evidence=[evidence()],
    )

    assert [item["type"] for item in candidates] == ["ENFORCEMENT_GAP", "STALE_CONTROL"]


def test_remote_deleted_unique_work_becomes_preservation_candidate() -> None:
    branch_subject = {"type": "local_branch", "identifier": "feature-gone"}
    branch_evidence = evidence("ev_branch")
    branch_evidence["kind"] = "git_state"
    branch_evidence["subject"] = branch_subject

    candidates = correlate(
        control_results=[result(
            "HYGIENE-004",
            subject=branch_subject,
            evidence_ids=["ev_branch"],
            reason="preservation_risk:feature-gone:remote_deleted_local_unique_work",
        )],
        evidence=[branch_evidence],
    )

    assert candidates[0]["type"] == "PRESERVATION_RISK"
    assert candidates[0]["proposed_severity"] == "HIGH"


def test_integrated_stale_branch_becomes_cleanup_candidate() -> None:
    branch_subject = {"type": "local_branch", "identifier": "feature-old"}
    branch_evidence = evidence("ev_branch")
    branch_evidence["kind"] = "git_state"
    branch_evidence["subject"] = branch_subject

    candidates = correlate(
        control_results=[result(
            "HYGIENE-001",
            subject=branch_subject,
            evidence_ids=["ev_branch"],
            reason="cleanup_candidate:feature-old",
        )],
        evidence=[branch_evidence],
    )

    assert candidates[0]["type"] == "CLEANUP_CANDIDATE"
    assert candidates[0]["proposed_severity"] == "INFO"


def test_finding_with_missing_evidence_is_rejected() -> None:
    with pytest.raises(CorrelationError, match="missing evidence"):
        correlate(
            control_results=[result("CI-OPS-006", evidence_ids=["ev_missing"])],
            evidence=[evidence("ev_present")],
        )


def test_unmapped_material_finding_gets_generic_candidate() -> None:
    candidates = correlate(
        control_results=[result(
            "GH-GOV-001",
            reason="default_branch_governance_absent",
        )],
        evidence=[evidence()],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["control_id"] == "GH-GOV-001"
    assert candidate["type"] == "CONTROL_FINDING"
    assert candidate["proposed_severity"] == "MEDIUM"
    assert candidate["proposed_confidence"] == "HIGH"
    assert candidate["evidence_ids"] == ["ev_1"]
    validate_document("candidate-finding.v1", candidate)


def test_unmapped_material_finding_with_missing_evidence_is_rejected() -> None:
    with pytest.raises(CorrelationError, match="missing evidence"):
        correlate(
            control_results=[result(
                "GH-GOV-001",
                evidence_ids=["ev_missing"],
                reason="default_branch_governance_absent",
            )],
            evidence=[evidence("ev_present")],
        )


def test_chronic_optional_workflow_becomes_canonical_candidate() -> None:
    candidates = correlate(
        control_results=[result("CI-OPS-003", reason="chronic_failure:runs=10,failure_rate=0.800,consecutive_failures=3")],
        evidence=[evidence()],
    )
    assert candidates[0]["type"] == "CHRONIC_FAILURE"


def test_flaky_workflow_becomes_canonical_candidate() -> None:
    candidates = correlate(
        control_results=[result("CI-OPS-005", reason="rerun_recovery:" + "a" * 40)],
        evidence=[evidence()],
    )
    assert candidates[0]["type"] == "FLAKY_JOB"


def test_stale_required_check_becomes_canonical_candidate() -> None:
    candidates = correlate(
        control_results=[result("GH-GOV-003", reason="stale_required_checks:old-check")],
        evidence=[evidence()],
    )
    assert candidates[0]["type"] == "STALE_REQUIRED_CHECK"


def test_runner_deprecation_becomes_canonical_candidate() -> None:
    candidates = correlate(
        control_results=[result("CI-STATIC-008", reason="runner_lifecycle_risk:macos-14=retiring")],
        evidence=[evidence()],
    )
    assert candidates[0]["type"] == "DEPRECATION_RISK"
