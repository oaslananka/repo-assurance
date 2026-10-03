from __future__ import annotations

from repo_assurance.core.completeness import compute_domain_coverage
from repo_assurance.evaluators.providers import evaluate_providers


SHA = "a" * 40


def provider_evidence(
    provider_id: str,
    *,
    adapter_id: str,
    conclusion: str = "success",
    inventory_access: str = "UNAVAILABLE",
    items: list[dict] | None = None,
) -> dict:
    observation = {
        "schema_version": "provider-state/v1",
        "provider": {
            "id": provider_id,
            "display_name": provider_id,
            "adapter_id": adapter_id,
            "known_adapter": adapter_id != "generic-github-check/v1",
        },
        "discovery": {
            "mechanism": "github_check_run",
            "check_run_id": 10,
            "app_id": 20,
            "app_slug": provider_id,
        },
        "capabilities": [],
        "entitlement": {"state": "UNKNOWN"},
        "execution": {
            "observed": True,
            "check_name": "provider check",
            "status": "completed",
            "conclusion": conclusion,
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
        },
        "coverage": {
            "target_commit_sha": SHA,
            "target_binding": "ATTACHED",
            "scan_scope": "UNKNOWN",
            "scope": {},
        },
        "inventory": {
            "access_state": inventory_access,
            "reason": None if inventory_access == "AVAILABLE" else "provider_inventory_not_connected",
            "items": items or [],
        },
        "enforcement": {"state": "NOT_REQUIRED"},
        "evidence_gaps": [] if inventory_access == "AVAILABLE" else ["provider_issue_inventory"],
    }
    return {
        "schema_version": "evidence/v1",
        "id": f"ev_provider_{provider_id}",
        "kind": "provider_state",
        "source": {
            "provider": provider_id,
            "mechanism": "github-check-run",
            "collector": "provider-discovery/v1",
        },
        "subject": {"type": "provider", "identifier": provider_id},
        "observation": observation,
        "snapshot": {"repository": "acme/demo", "target_commit_sha": SHA},
        "collected_at": "2026-10-03T03:00:00Z",
        "visibility": {
            "completeness": "complete" if inventory_access == "AVAILABLE" else "partial",
            "permission_limited": inventory_access == "UNKNOWN_PERMISSION",
            "retention_limited": False,
        },
        "redactions": [],
    }


def result(results: list[dict], control_id: str) -> list[dict]:
    return [item for item in results if item["control_id"] == control_id]


def test_successful_sonar_execution_with_unavailable_inventory_is_not_provider_pass() -> None:
    evidence = provider_evidence("sonarqube-cloud", adapter_id="sonarqube-cloud/v1")
    results = evaluate_providers([evidence])

    assert result(results, "PROV-001")[0]["state"] == "PASS"
    assert result(results, "PROV-002")[0]["state"] == "UNAVAILABLE"
    assert result(results, "PROV-003")[0]["state"] == "UNAVAILABLE"

    coverage = compute_domain_coverage(
        audit_plan={
            "controls": [
                {"control_id": "PROV-001", "applicable": True},
                {"control_id": "PROV-002", "applicable": True},
                {"control_id": "PROV-003", "applicable": True},
            ]
        },
        control_results=results,
        evidence=[evidence],
    )
    assert coverage["external_providers"] == "PARTIAL"


def test_successful_socket_execution_with_unavailable_inventory_is_not_provider_pass() -> None:
    evidence = provider_evidence("socket", adapter_id="socket/v1")
    results = evaluate_providers([evidence])

    assert result(results, "PROV-001")[0]["state"] == "PASS"
    assert result(results, "PROV-002")[0]["state"] == "UNAVAILABLE"
    assert result(results, "PROV-003")[0]["state"] == "UNAVAILABLE"


def test_open_provider_dependency_advisory_uses_stable_dependency_subject() -> None:
    evidence = provider_evidence(
        "socket",
        adapter_id="socket/v1",
        inventory_access="AVAILABLE",
        items=[{
            "kind": "dependency_vulnerability",
            "state": "open",
            "upstream_id": "GHSA-1234-5678-9999",
            "package": "urllib3",
            "severity": "high",
        }],
    )

    findings = result(evaluate_providers([evidence]), "PROV-003")

    assert len(findings) == 1
    assert findings[0]["state"] == "FINDING"
    assert findings[0]["subject"] == {
        "type": "dependency",
        "identifier": "GHSA-1234-5678-9999",
        "qualifiers": {
            "package": "urllib3",
            "provider": "socket",
            "severity": "high",
        },
    }
    assert findings[0]["candidate_finding_ids"] == [
        "candidate_PROV-003_socket_GHSA-1234-5678-9999"
    ]

def provider_discovery(access_state: str = "AVAILABLE") -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_provider_discovery",
        "kind": "provider_state",
        "source": {
            "provider": "github",
            "mechanism": "check-run-discovery",
            "collector": "provider-discovery/v1",
        },
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": {
            "access_state": access_state,
            "detected_provider_ids": [],
            "source_evidence_id": "ev_github_checks",
        },
        "snapshot": {"repository": "acme/demo", "target_commit_sha": SHA},
        "collected_at": "2026-10-03T03:00:00Z",
        "visibility": {
            "completeness": "complete" if access_state == "AVAILABLE" else "unknown",
            "permission_limited": access_state == "UNKNOWN_PERMISSION",
            "retention_limited": False,
        },
        "redactions": [],
    }


def test_no_detected_provider_is_not_enabled_not_a_finding() -> None:
    results = evaluate_providers([provider_discovery()])

    assert [item["state"] for item in results] == [
        "NOT_ENABLED",
        "NOT_ENABLED",
        "NOT_ENABLED",
    ]
    assert all(item["evidence_ids"] == ["ev_provider_discovery"] for item in results)


def test_provider_discovery_permission_gap_is_not_pass() -> None:
    results = evaluate_providers([provider_discovery("UNKNOWN_PERMISSION")])

    assert [item["state"] for item in results] == [
        "UNKNOWN_PERMISSION",
        "UNKNOWN_PERMISSION",
        "UNKNOWN_PERMISSION",
    ]


def test_failed_provider_execution_is_a_material_finding() -> None:
    evidence = provider_evidence(
        "sonarqube-cloud",
        adapter_id="sonarqube-cloud/v1",
        conclusion="failure",
    )

    item = result(evaluate_providers([evidence]), "PROV-001")[0]

    assert item["state"] == "FINDING"
    assert item["candidate_finding_ids"] == [
        "candidate_PROV-001_sonarqube-cloud_execution_failure"
    ]
