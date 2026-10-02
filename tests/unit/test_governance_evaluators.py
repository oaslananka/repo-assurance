from __future__ import annotations

from repo_assurance.evaluators.governance import evaluate_governance


SUBJECT = {"type": "repository", "identifier": "acme/demo"}


def evidence(evidence_id: str, observation: dict) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "github_state",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": SUBJECT,
        "observation": observation,
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def repository_state(delete_branch_on_merge: bool = True) -> dict:
    return evidence("ev_github_repository", {
        "access_state": "AVAILABLE",
        "full_name": "acme/demo",
        "default_branch": "main",
        "delete_branch_on_merge": delete_branch_on_merge,
    })


def branch_state(*, protected: bool, required: list[str] | None = None) -> dict:
    return evidence("ev_github_default_branch", {
        "access_state": "AVAILABLE",
        "name": "main",
        "protected": protected,
        "required_status_checks": required or [],
    })


def rulesets(items: list[dict]) -> dict:
    return evidence("ev_github_rulesets", {"access_state": "AVAILABLE", "rulesets": items})


def checks(names: list[str]) -> dict:
    return evidence("ev_github_checks", {"access_state": "AVAILABLE", "check_names": names})


def result(results: list[dict], control_id: str) -> dict:
    return next(item for item in results if item["control_id"] == control_id)


def test_active_default_branch_ruleset_counts_as_governance() -> None:
    rs = {
        "id": 1, "name": "main", "enforcement": "active", "target": "branch",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [], "rules": [{"type": "pull_request"}],
    }
    results = evaluate_governance([repository_state(), branch_state(protected=False), rulesets([rs])])
    assert result(results, "GH-GOV-001")["state"] == "PASS"


def test_unprotected_branch_without_active_ruleset_is_finding() -> None:
    results = evaluate_governance([repository_state(), branch_state(protected=False), rulesets([])])
    item = result(results, "GH-GOV-001")
    assert item["state"] == "FINDING"
    assert item["reason"] == "default_branch_governance_absent"
    assert item["candidate_finding_ids"]


def test_stale_required_check_is_finding() -> None:
    results = evaluate_governance([
        repository_state(),
        branch_state(protected=True, required=["test", "old-check"]),
        rulesets([]),
        checks(["test", "lint"]),
    ])
    item = result(results, "GH-GOV-003")
    assert item["state"] == "FINDING"
    assert item["reason"] == "stale_required_checks:old-check"


def test_current_required_checks_pass() -> None:
    results = evaluate_governance([
        repository_state(),
        branch_state(protected=True, required=["test", "lint"]),
        rulesets([]),
        checks(["test", "lint"]),
    ])
    assert result(results, "GH-GOV-003")["state"] == "PASS"


def test_always_bypass_actor_is_review_finding() -> None:
    rs = {
        "id": 1, "name": "main", "enforcement": "active", "target": "branch",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        "rules": [{"type": "pull_request"}],
    }
    results = evaluate_governance([repository_state(), branch_state(protected=False), rulesets([rs])])
    item = result(results, "GH-GOV-007")
    assert item["state"] == "FINDING"
    assert item["reason"] == "always_bypass_actors:1"


def test_ruleset_permission_gap_is_not_reported_as_clean() -> None:
    denied = evidence("ev_github_rulesets", {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"})
    results = evaluate_governance([repository_state(), branch_state(protected=False), denied])
    assert result(results, "GH-GOV-001")["state"] == "UNKNOWN_PERMISSION"
    assert result(results, "GH-GOV-003")["state"] == "UNKNOWN_PERMISSION"
    assert result(results, "GH-GOV-007")["state"] == "UNKNOWN_PERMISSION"


def test_auto_delete_disabled_is_observed_not_automatically_a_finding() -> None:
    results = evaluate_governance([repository_state(False), branch_state(protected=True), rulesets([])])
    item = result(results, "GH-GOV-008")
    assert item["state"] == "PASS"
    assert item["reason"] == "auto_delete_merged_branches:disabled"
