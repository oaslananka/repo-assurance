from __future__ import annotations

from repo_assurance.core.gates import (
    build_required_gate_mapping_evidence,
    resolve_required_gate_mapping,
)
from repo_assurance.core.schema import validate_document



def evidence(evidence_id: str, observation: dict) -> dict:
    return {
        "id": evidence_id,
        "observation": observation,
        "visibility": {
            "completeness": "complete" if observation.get("access_state") == "AVAILABLE" else "unknown",
            "permission_limited": observation.get("access_state") == "UNKNOWN_PERMISSION",
            "retention_limited": False,
        },
    }


def governance(*, required_app_id: int | None = 15368, check_app_id: int = 15368) -> list[dict]:
    return [
        evidence("ev_github_default_branch", {
            "access_state": "AVAILABLE",
            "required_status_checks": ["test"],
            "required_status_check_details": [{"context": "test", "app_id": required_app_id}],
        }),
        evidence("ev_github_rulesets", {"access_state": "AVAILABLE", "rulesets": []}),
        evidence("ev_github_checks", {
            "access_state": "AVAILABLE",
            "check_names": ["test"],
            "check_runs": [{
                "id": 111094972560,
                "name": "test",
                "app_id": check_app_id,
                "app_slug": "github-actions",
                "workflow_run_id": 37085552168,
                "job_id": 111094972560,
            }],
        }),
    ]


def history(workflow_id: str = "373566427", run_id: int = 37085552168) -> list[dict]:
    return [{
        "id": f"ev_github_workflow_history_{workflow_id}",
        "subject": {
            "type": "github_workflow",
            "identifier": ".github/workflows/ci.yml",
            "display_name": "CI",
        },
        "observation": {
            "access_state": "AVAILABLE",
            "workflow_id": workflow_id,
            "workflow_name": "CI",
            "runs": [{"id": run_id, "head_sha": "a" * 40}],
        },
    }]


def test_required_check_maps_through_check_run_to_parent_workflow() -> None:
    mapping = resolve_required_gate_mapping(governance(), history())

    assert mapping["complete"] is True
    assert mapping["required_workflow_ids"] == ["373566427"]
    assert mapping["unresolved"] == []
    assert mapping["mappings"] == [{
        "context": "test",
        "app_id": 15368,
        "check_run_ids": [111094972560],
        "job_ids": [111094972560],
        "workflow_run_ids": [37085552168],
        "workflow_id": "373566427",
        "workflow_name": "CI",
        "workflow_path": ".github/workflows/ci.yml",
    }]


def test_required_check_app_identity_must_match_when_policy_pins_app() -> None:
    mapping = resolve_required_gate_mapping(
        governance(required_app_id=999, check_app_id=15368),
        history(),
    )

    assert mapping["complete"] is False
    assert mapping["required_workflow_ids"] == []
    assert mapping["unresolved"][0]["context"] == "test"
    assert mapping["unresolved"][0]["reason"] == "required_check_not_produced_by_expected_app"


def test_same_required_context_mapping_to_multiple_workflows_is_ambiguous() -> None:
    items = governance(required_app_id=None)
    items[-1]["observation"]["check_runs"].append({
        "id": 222,
        "name": "test",
        "app_id": 15368,
        "app_slug": "github-actions",
        "workflow_run_id": 444,
        "job_id": 222,
    })
    history_items = history() + [{
        "id": "ev_github_workflow_history_999",
        "subject": {"type": "github_workflow", "identifier": ".github/workflows/other.yml", "display_name": "Other"},
        "observation": {
            "access_state": "AVAILABLE",
            "workflow_id": "999",
            "workflow_name": "Other",
            "runs": [{"id": 444, "head_sha": "a" * 40}],
        },
    }]

    mapping = resolve_required_gate_mapping(items, history_items)

    assert mapping["complete"] is False
    assert mapping["required_workflow_ids"] == []
    assert mapping["unresolved"][0]["reason"] == "required_check_maps_to_multiple_workflows"


def test_missing_check_run_visibility_keeps_mapping_incomplete() -> None:
    items = governance()
    items[-1] = evidence("ev_github_checks", {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"})

    mapping = resolve_required_gate_mapping(items, history())

    assert mapping["complete"] is False
    assert mapping["permission_limited"] is True
    assert mapping["required_workflow_ids"] == []


def test_mapping_evidence_is_schema_valid_and_preserves_sources() -> None:
    governance_items = governance()
    history_items = history()

    item = build_required_gate_mapping_evidence(
        repository="acme/demo",
        target_commit_sha="a" * 40,
        governance=governance_items,
        history=history_items,
    )

    validate_document("evidence.v1", item)
    assert item["id"] == "ev_required_gate_mapping"
    assert item["kind"] == "inference"
    assert item["observation"]["complete"] is True
    assert item["observation"]["required_workflow_ids"] == ["373566427"]
    assert item["observation"]["source_evidence_ids"] == [
        "ev_github_checks",
        "ev_github_default_branch",
        "ev_github_rulesets",
        "ev_github_workflow_history_373566427",
    ]
