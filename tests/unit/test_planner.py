from __future__ import annotations

import pytest

from repo_assurance.core.planner import RepositoryCapabilities, build_audit_plan
from repo_assurance.core.schema import validate_document


def control(
    control_id: str,
    *,
    all_caps: list[str] | None = None,
    any_caps: list[str] | None = None,
    excluded: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "control/v1",
        "id": control_id,
        "title": control_id,
        "domain": "test",
        "description": "Fixture control.",
        "evaluator": "fixture.evaluate",
        "applicability": {
            "all_capabilities": all_caps or [],
            "any_capabilities": any_caps or [],
            "excluded_repository_types": excluded or [],
        },
        "evidence_requirements": {"minimum_kinds": ["source"], "minimum_items": 1},
        "evaluation": {"time_sensitive": False, "correlation_required": False, "dynamic_execution": False},
        "outputs": {"allowed_states": ["PASS", "FINDING", "NOT_APPLICABLE"]},
    }


REPOSITORY = {
    "owner": "oaslananka",
    "name": "repo-assurance",
    "full_name": "oaslananka/repo-assurance",
    "repository_type": "cli",
}
SNAPSHOT = {"target_branch": "main", "target_commit_sha": "a" * 40}


def test_every_catalog_control_is_accounted_for() -> None:
    catalog = [control("TEST-003"), control("TEST-001"), control("TEST-002")]

    plan = build_audit_plan(
        catalog=catalog,
        capabilities=RepositoryCapabilities({"github": True}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    assert [entry["control_id"] for entry in plan["controls"]] == ["TEST-001", "TEST-002", "TEST-003"]


def test_missing_required_capability_marks_control_not_applicable() -> None:
    catalog = [control("TEST-001", all_caps=["github", "rulesets"])]

    plan = build_audit_plan(
        catalog=catalog,
        capabilities=RepositoryCapabilities({"github": True, "rulesets": False}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    entry = plan["controls"][0]
    assert entry["applicable"] is False
    assert entry["reason"] == "missing_capabilities:rulesets"


def test_any_capability_requires_at_least_one_available() -> None:
    catalog = [control("TEST-001", any_caps=["codeql", "semgrep"])]

    plan = build_audit_plan(
        catalog=catalog,
        capabilities=RepositoryCapabilities({"codeql": False, "semgrep": True}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    assert plan["controls"][0]["applicable"] is True


def test_no_any_capability_available_marks_not_applicable() -> None:
    catalog = [control("TEST-001", any_caps=["codeql", "semgrep"])]

    plan = build_audit_plan(
        catalog=catalog,
        capabilities=RepositoryCapabilities({"codeql": False, "semgrep": False}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    assert plan["controls"][0] == {
        "control_id": "TEST-001",
        "applicable": False,
        "reason": "missing_any_capability:codeql,semgrep",
    }


def test_excluded_repository_type_marks_not_applicable() -> None:
    catalog = [control("TEST-001", excluded=["cli"])]

    plan = build_audit_plan(
        catalog=catalog,
        capabilities=RepositoryCapabilities({}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    assert plan["controls"][0]["reason"] == "excluded_repository_type:cli"


def test_standard_mode_uses_approved_history_budgets() -> None:
    plan = build_audit_plan(
        catalog=[control("TEST-001")],
        capabilities=RepositoryCapabilities({}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    assert plan["budgets"]["github"] == {
        "max_runs_per_workflow": 100,
        "max_history_days": 90,
    }
    assert plan["budgets"]["current_baseline"] == {"max_external_lookups": 20}


def test_generated_plan_satisfies_canonical_schema() -> None:
    plan = build_audit_plan(
        catalog=[control("TEST-001")],
        capabilities=RepositoryCapabilities({"github": True}),
        repository=REPOSITORY,
        snapshot=SNAPSHOT,
        mode="standard",
    )

    validate_document("audit-plan.v1", plan)


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported audit mode"):
        build_audit_plan(
            catalog=[control("TEST-001")],
            capabilities=RepositoryCapabilities({}),
            repository=REPOSITORY,
            snapshot=SNAPSHOT,
            mode="turbo",
        )
