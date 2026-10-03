from __future__ import annotations

from repo_assurance.evaluators.github_security import evaluate_github_security


SHA = "a" * 40
OTHER_SHA = "b" * 40


def evidence(
    evidence_id: str,
    observation: dict,
    *,
    kind: str = "github_state",
    completeness: str = "complete",
    permission_limited: bool = False,
) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {
            "provider": "github",
            "mechanism": "fixture",
            "collector": "fixture/v1",
        },
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": observation,
        "snapshot": {"repository": "acme/demo", "target_commit_sha": SHA},
        "collected_at": "2026-10-03T00:00:00Z",
        "visibility": {
            "completeness": completeness,
            "permission_limited": permission_limited,
            "retention_limited": False,
        },
        "redactions": [],
    }


def repository_security(
    *,
    secret_scanning: str = "enabled",
    push_protection: str = "enabled",
    dependabot_updates: str = "enabled",
) -> dict:
    return evidence("ev_github_repository", {
        "access_state": "AVAILABLE",
        "security_and_analysis": {
            "secret_scanning": secret_scanning,
            "secret_scanning_push_protection": push_protection,
            "dependabot_security_updates": dependabot_updates,
        },
    })


def available_empty(evidence_id: str, key: str, *, kind: str = "github_state") -> dict:
    return evidence(
        evidence_id,
        {"access_state": "AVAILABLE", key: []},
        kind=kind,
    )


def by_control(results: list[dict], control_id: str) -> list[dict]:
    return [item for item in results if item["control_id"] == control_id]


def complete_inputs() -> list[dict]:
    return [
        repository_security(),
        evidence("ev_github_code_scanning_analyses", {
            "access_state": "AVAILABLE",
            "analyses": [{
                "id": 1,
                "commit_sha": SHA,
                "ref": "refs/heads/main",
                "error": "",
                "tool": {"name": "CodeQL", "version": "2.27.1"},
            }],
        }),
        available_empty("ev_github_code_scanning_alerts", "alerts"),
        available_empty("ev_github_secret_scanning_alerts", "alerts"),
        evidence(
            "ev_github_dependency_sbom",
            {
                "access_state": "AVAILABLE",
                "sbom": {
                    "name": "com.github.acme/demo",
                    "spdx_version": "SPDX-2.3",
                    "packages_count": 2,
                    "relationships_count": 1,
                },
            },
            kind="dependency_state",
        ),
        available_empty(
            "ev_github_dependabot_alerts",
            "alerts",
            kind="dependency_state",
        ),
    ]


def test_historical_code_scanning_without_target_coverage_is_finding() -> None:
    items = complete_inputs()
    analyses = next(
        item for item in items if item["id"] == "ev_github_code_scanning_analyses"
    )
    analyses["observation"]["analyses"][0]["commit_sha"] = OTHER_SHA

    results = evaluate_github_security(items)

    item = by_control(results, "GH-SEC-001")[0]
    assert item["state"] == "FINDING"
    assert item["reason"] == f"code_scanning_target_not_covered:{SHA}"
    assert item["candidate_finding_ids"] == [
        "candidate_GH-SEC-001_target_not_covered"
    ]


def test_target_code_scanning_analysis_is_pass() -> None:
    item = by_control(
        evaluate_github_security(complete_inputs()),
        "GH-SEC-001",
    )[0]

    assert item["state"] == "PASS"
    assert item["reason"] == "code_scanning_target_covered:1"


def test_open_code_scanning_alert_is_material_per_alert_result() -> None:
    items = complete_inputs()
    alerts = next(
        item for item in items if item["id"] == "ev_github_code_scanning_alerts"
    )
    alerts["observation"]["alerts"] = [{
        "number": 42,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {
            "id": "py/sql-injection",
            "security_severity_level": "high",
        },
        "most_recent_instance": {
            "commit_sha": SHA,
            "ref": "refs/heads/main",
            "state": "open",
        },
    }]

    result = by_control(
        evaluate_github_security(items),
        "GH-SEC-002",
    )[0]

    assert result["state"] == "FINDING"
    assert result["subject"]["identifier"] == "github-code-scanning:42"
    assert result["candidate_finding_ids"] == [
        "candidate_GH-SEC-002_alert_42"
    ]


def test_permission_limited_alert_visibility_never_becomes_pass() -> None:
    items = complete_inputs()
    index = next(
        idx for idx, item in enumerate(items)
        if item["id"] == "ev_github_code_scanning_alerts"
    )
    items[index] = evidence(
        "ev_github_code_scanning_alerts",
        {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"},
        completeness="unknown",
        permission_limited=True,
    )

    result = by_control(
        evaluate_github_security(items),
        "GH-SEC-002",
    )[0]

    assert result["state"] == "UNKNOWN_PERMISSION"
    assert result["reason"] == "code_scanning_alert_visibility:UNKNOWN_PERMISSION"


def test_secret_scanning_and_push_protection_disabled_is_finding() -> None:
    items = complete_inputs()
    items[0] = repository_security(push_protection="disabled")

    result = by_control(
        evaluate_github_security(items),
        "GH-SEC-003",
    )[0]

    assert result["state"] == "FINDING"
    assert "secret_scanning_push_protection=disabled" in result["reason"]


def test_dependency_sbom_visibility_is_pass_without_claiming_no_vulnerabilities() -> None:
    result = by_control(
        evaluate_github_security(complete_inputs()),
        "DEP-001",
    )[0]

    assert result["state"] == "PASS"
    assert result["reason"] == "dependency_sbom_visible:packages=2"


def test_dependabot_security_updates_disabled_is_finding() -> None:
    items = complete_inputs()
    items[0] = repository_security(dependabot_updates="disabled")

    result = by_control(
        evaluate_github_security(items),
        "DEP-002",
    )[0]

    assert result["state"] == "FINDING"
    assert result["reason"] == "dependabot_security_updates=disabled"


def test_open_dependabot_alert_uses_advisory_dependency_subject() -> None:
    items = complete_inputs()
    alerts = next(
        item for item in items if item["id"] == "ev_github_dependabot_alerts"
    )
    alerts["observation"]["alerts"] = [{
        "number": 8,
        "state": "open",
        "dependency": {
            "package": "urllib3",
            "manifest_path": "pyproject.toml",
            "scope": "runtime",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-1234-5678-9999",
            "severity": "high",
        },
    }]

    result = by_control(
        evaluate_github_security(items),
        "DEP-003",
    )[0]

    assert result["state"] == "FINDING"
    assert result["subject"]["type"] == "dependency"
    assert result["subject"]["identifier"] == "GHSA-1234-5678-9999"
    assert result["subject"]["qualifiers"]["package"] == "urllib3"
    assert result["candidate_finding_ids"] == [
        "candidate_DEP-003_alert_8"
    ]
