from __future__ import annotations

from repo_assurance.collectors.providers import (
    collect_provider_discovery,
    collect_provider_states,
    provider_summaries,
)
from repo_assurance.core.schema import validate_document


SHA = "a" * 40


def github_checks(check_runs: list[dict]) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_github_checks",
        "kind": "github_state",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": {
            "access_state": "AVAILABLE",
            "check_names": sorted({item["name"] for item in check_runs}),
            "check_runs": check_runs,
        },
        "snapshot": {"repository": "acme/demo", "target_commit_sha": SHA},
        "collected_at": "2026-10-03T03:00:00Z",
        "visibility": {
            "completeness": "complete",
            "permission_limited": False,
            "retention_limited": False,
        },
        "redactions": [],
    }


def test_unknown_provider_discovery_does_not_invent_capabilities() -> None:
    items = collect_provider_states(
        github_checks([{
            "id": 10,
            "name": "Acme Security",
            "status": "completed",
            "conclusion": "success",
            "app_id": 999,
            "app_slug": "acme-security",
            "app_name": "Acme Security",
            "details_url": "https://example.invalid/result/10",
            "external_id": "run-10",
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
            "check_suite_id": 100,
            "workflow_run_id": None,
            "job_id": None,
        }]),
        required_checks=[],
    )

    assert len(items) == 1
    item = items[0]
    validate_document("evidence.v1", item)
    validate_document("provider-state.v1", item["observation"])

    state = item["observation"]
    assert state["provider"] == {
        "id": "acme-security",
        "display_name": "Acme Security",
        "adapter_id": "generic-github-check/v1",
        "known_adapter": False,
    }
    assert state["capabilities"] == []
    assert state["inventory"]["access_state"] == "UNAVAILABLE"
    assert state["inventory"]["reason"] == "provider_inventory_not_connected"
    assert state["coverage"]["target_binding"] == "ATTACHED"
    assert state["coverage"]["scan_scope"] == "UNKNOWN"
    assert state["entitlement"]["state"] == "UNKNOWN"


def test_sonarqube_cloud_adapter_extracts_grounded_scope_but_not_inventory_health() -> None:
    items = collect_provider_states(
        github_checks([{
            "id": 11,
            "name": "SonarCloud Code Analysis",
            "status": "completed",
            "conclusion": "success",
            "app_id": 12526,
            "app_slug": "sonarqubecloud",
            "app_name": "SonarQubeCloud",
            "details_url": "https://sonarcloud.io/dashboard?id=acme_demo&branch=main",
            "external_id": "",
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
            "check_suite_id": 101,
            "workflow_run_id": None,
            "job_id": None,
        }]),
        required_checks=[{"context": "SonarCloud Code Analysis", "app_id": 12526}],
    )

    state = items[0]["observation"]
    assert state["provider"]["id"] == "sonarqube-cloud"
    assert state["provider"]["adapter_id"] == "sonarqube-cloud/v1"
    assert state["provider"]["known_adapter"] is True
    assert state["capabilities"] == ["issue_inventory", "quality_gate"]
    assert state["coverage"]["scope"] == {"project_key": "acme_demo", "branch": "main"}
    assert state["inventory"]["access_state"] == "UNAVAILABLE"
    assert state["enforcement"]["state"] == "REQUIRED"
    assert items[0]["visibility"]["completeness"] == "partial"


def test_socket_adapter_extracts_sbom_scope_and_keeps_alert_visibility_explicit() -> None:
    items = collect_provider_states(
        github_checks([{
            "id": 12,
            "name": "Socket Security: Project Report",
            "status": "completed",
            "conclusion": "success",
            "app_id": 156372,
            "app_slug": "socket-security",
            "app_name": "Socket Security",
            "details_url": "https://socket.dev/dashboard/org/acme/sbom/11111111-2222-3333-4444-555555555555",
            "external_id": "177235533",
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
            "check_suite_id": 102,
            "workflow_run_id": None,
            "job_id": None,
        }]),
        required_checks=[],
    )

    state = items[0]["observation"]
    assert state["provider"]["id"] == "socket"
    assert state["provider"]["adapter_id"] == "socket/v1"
    assert state["capabilities"] == ["dependency_alerts", "dependency_inventory"]
    assert state["coverage"]["scope"] == {
        "organization": "acme",
        "scope_type": "sbom",
        "scope_id": "11111111-2222-3333-4444-555555555555",
    }
    assert state["inventory"]["access_state"] == "UNAVAILABLE"
    assert state["enforcement"]["state"] == "NOT_REQUIRED"

def test_provider_discovery_distinguishes_no_provider_from_missing_visibility() -> None:
    checks = github_checks([])
    discovery = collect_provider_discovery(checks)
    states = collect_provider_states(checks, required_checks=[])

    assert states == []
    assert discovery["observation"] == {
        "access_state": "AVAILABLE",
        "detected_provider_ids": [],
        "source_evidence_id": "ev_github_checks",
    }
    assert discovery["visibility"]["completeness"] == "complete"


def test_provider_summaries_are_schema_valid_report_values() -> None:
    states = collect_provider_states(
        github_checks([{
            "id": 20,
            "name": "Socket Security: Project Report",
            "status": "completed",
            "conclusion": "success",
            "app_id": 156372,
            "app_slug": "socket-security",
            "app_name": "Socket Security",
            "details_url": "https://socket.dev/dashboard/org/acme/sbom/abc",
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
        }]),
        required_checks=[],
    )

    summaries = provider_summaries(states)

    assert len(summaries) == 1
    assert summaries[0]["schema_version"] == "provider-state/v1"
    assert summaries[0]["provider"]["id"] == "socket"
    validate_document("provider-state.v1", summaries[0])

def test_provider_enforcement_respects_pinned_app_identity() -> None:
    items = collect_provider_states(
        github_checks([{
            "id": 13,
            "name": "SonarCloud Code Analysis",
            "status": "completed",
            "conclusion": "success",
            "app_id": 12526,
            "app_slug": "sonarqubecloud",
            "app_name": "SonarQubeCloud",
            "details_host": "sonarcloud.io",
            "details_path": "/dashboard",
            "details_query": {"id": "acme_demo", "branch": "main"},
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
        }]),
        required_checks=[{
            "context": "SonarCloud Code Analysis",
            "app_id": 999999,
        }],
    )

    assert items[0]["observation"]["enforcement"] == {
        "state": "NOT_REQUIRED"
    }

