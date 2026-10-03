from __future__ import annotations

from repo_assurance.core.completeness import compute_domain_coverage


def plan(entries: list[tuple[str, bool]]) -> dict:
    return {
        "schema_version": "audit-plan/v1",
        "audit_id": "audit_1",
        "mode": "standard",
        "repository": {"owner": "acme", "name": "demo", "full_name": "acme/demo"},
        "snapshot": {"target_branch": "main", "target_commit_sha": "a" * 40},
        "capabilities": {},
        "controls": [
            {"control_id": control_id, "applicable": applicable, **({} if applicable else {"reason": "not_applicable"})}
            for control_id, applicable in entries
        ],
        "budgets": {
            "github": {"max_runs_per_workflow": 100, "max_history_days": 90},
            "current_baseline": {"max_external_lookups": 20},
        },
    }


def result(control_id: str, state: str, *, evidence_ids: list[str] | None = None) -> dict:
    return {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "evidence_ids": evidence_ids or [],
        "candidate_finding_ids": [],
        "evaluated_at": "2026-10-02T00:00:00Z",
    }


def evidence(evidence_id: str, *, completeness: str = "complete", retention_limited: bool = False) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "github_history",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "github_workflow", "identifier": "10"},
        "observation": {},
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {
            "completeness": completeness,
            "permission_limited": False,
            "retention_limited": retention_limited,
        },
        "redactions": [],
    }


def test_findings_do_not_make_verified_domain_partial() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("GH-GOV-001", True), ("GH-GOV-003", True)]),
        control_results=[
            result("GH-GOV-001", "PASS"),
            result("GH-GOV-003", "FINDING"),
        ],
    )

    assert coverage["github_governance"] == "VERIFIED"


def test_domain_permission_gap_is_distinct_from_verified_domain() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("GH-GOV-001", True), ("GH-SEC-001", True)]),
        control_results=[
            result("GH-GOV-001", "PASS"),
            result("GH-SEC-001", "UNKNOWN_PERMISSION"),
        ],
    )

    assert coverage["github_governance"] == "VERIFIED"
    assert coverage["github_security"] == "UNKNOWN_PERMISSION"


def test_partial_and_verified_controls_make_domain_partial() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("CI-OPS-001", True), ("CI-OPS-003", True)]),
        control_results=[
            result("CI-OPS-001", "PASS"),
            result("CI-OPS-003", "INCONCLUSIVE"),
        ],
    )

    assert coverage["ci_history"] == "PARTIAL"


def test_retention_limited_evidence_prevents_verified_history_claim() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("CI-OPS-003", True)]),
        control_results=[result("CI-OPS-003", "FINDING", evidence_ids=["ev_history"])],
        evidence=[evidence("ev_history", completeness="partial", retention_limited=True)],
    )

    assert coverage["ci_history"] == "PARTIAL"


def test_all_non_applicable_controls_make_domain_not_applicable() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("HYGIENE-001", False), ("HYGIENE-005", False)]),
        control_results=[],
    )

    assert coverage["workspace_hygiene"] == "NOT_APPLICABLE"


def test_missing_result_for_applicable_control_is_not_verified() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("SNAP-001", True)]),
        control_results=[],
    )

    assert coverage["snapshot"] == "UNAVAILABLE"


def test_unknown_error_only_domain_is_unavailable() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([("REPO-001", True)]),
        control_results=[result("REPO-001", "UNKNOWN_ERROR")],
    )

    assert coverage["repository"] == "UNAVAILABLE"

def test_dependency_permission_gap_prevents_verified_dependency_domain() -> None:
    coverage = compute_domain_coverage(
        audit_plan=plan([
            ("DEP-001", True),
            ("DEP-002", True),
            ("DEP-003", True),
        ]),
        control_results=[
            result("DEP-001", "PASS"),
            result("DEP-002", "PASS"),
            result("DEP-003", "UNKNOWN_PERMISSION"),
        ],
    )

    assert coverage["dependencies"] == "PARTIAL"
