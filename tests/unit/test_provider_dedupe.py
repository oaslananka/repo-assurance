from __future__ import annotations

from repo_assurance.core.correlation import correlate
from repo_assurance.core.dedupe import deduplicate_candidates


def evidence(evidence_id: str, kind: str) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {
            "provider": "fixture",
            "mechanism": "fixture",
            "collector": "fixture/v1",
        },
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": {},
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-03T03:00:00Z",
        "visibility": {
            "completeness": "complete",
            "permission_limited": False,
            "retention_limited": False,
        },
        "redactions": [],
    }


def control_result(control_id: str, evidence_id: str, *, qualifiers: dict) -> dict:
    return {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": "FINDING",
        "subject": {
            "type": "dependency",
            "identifier": "GHSA-1234-5678-9999",
            "qualifiers": qualifiers,
        },
        "evidence_ids": [evidence_id],
        "candidate_finding_ids": [f"candidate_{control_id}_GHSA-1234-5678-9999"],
        "evaluated_at": "2026-10-03T03:00:00Z",
    }


def test_github_and_provider_dependency_advisory_dedupe_to_one_canonical_group() -> None:
    candidates = correlate(
        control_results=[
            control_result(
                "DEP-003",
                "ev_github_dep",
                qualifiers={"package": "urllib3", "manifest_path": "pyproject.toml"},
            ),
            control_result(
                "PROV-003",
                "ev_socket",
                qualifiers={"package": "urllib3", "provider": "socket", "severity": "high"},
            ),
        ],
        evidence=[
            evidence("ev_github_dep", "dependency_state"),
            evidence("ev_socket", "provider_state"),
        ],
    )
    groups = deduplicate_candidates(candidates)

    assert len(groups) == 1
    assert groups[0]["type"] == "DEPENDENCY_VULNERABILITY"
    assert groups[0]["subject"] == {
        "type": "dependency",
        "identifier": "GHSA-1234-5678-9999",
    }
    assert groups[0]["control_ids"] == ["DEP-003", "PROV-003"]
    assert groups[0]["evidence_ids"] == ["ev_github_dep", "ev_socket"]
