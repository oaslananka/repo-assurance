from __future__ import annotations

import json

from repo_assurance.core.findings import materialize_findings
from repo_assurance.core.schema import validate_document
from repo_assurance.renderers.json_report import build_audit_report, render_json
from repo_assurance.renderers.markdown_report import render_markdown


def group(*, finding_type: str = "UNRELIABLE_GATE", identifier: str = ".github/workflows/ci.yml", fingerprint: str | None = None) -> dict:
    return {
        "fingerprint": fingerprint or ("sha256:" + "a" * 64),
        "type": finding_type,
        "subject": {"type": "github_workflow", "identifier": identifier},
        "root_discriminator": "required-unreliable-gate",
        "candidate_ids": ["candidate_1"],
        "control_ids": ["CI-OPS-006"],
        "evidence_ids": ["ev_history"],
        "proposed_severities": ["HIGH"],
        "proposed_confidences": ["CONFIRMED"],
    }


def base_plan() -> dict:
    return {
        "schema_version": "audit-plan/v1",
        "audit_id": "audit_1",
        "mode": "standard",
        "repository": {"owner": "acme", "name": "demo", "full_name": "acme/demo"},
        "snapshot": {"target_branch": "main", "target_commit_sha": "b" * 40},
        "capabilities": {"github": True},
        "controls": [
            {"control_id": "SNAP-001", "applicable": True},
            {"control_id": "CI-OPS-006", "applicable": True},
        ],
        "budgets": {
            "github": {"max_runs_per_workflow": 100, "max_history_days": 90},
            "current_baseline": {"max_external_lookups": 20},
        },
    }


def test_materialized_group_is_canonical_finding() -> None:
    findings = materialize_findings([group()], baseline_as_of="2026-10-02")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "UNRELIABLE_GATE"
    assert finding["severity"] == "HIGH"
    assert finding["priority"] == "P1"
    assert finding["evidence_ids"] == ["ev_history"]
    validate_document("finding.v1", finding)


def test_cleanup_candidate_materializes_as_observation() -> None:
    cleanup = group(finding_type="CLEANUP_CANDIDATE", identifier="feature-old", fingerprint="sha256:" + "c" * 64)
    cleanup["subject"] = {"type": "local_branch", "identifier": "feature-old"}
    cleanup["root_discriminator"] = "integrated-stale-branch"
    cleanup["control_ids"] = ["HYGIENE-001"]

    finding = materialize_findings([cleanup], baseline_as_of="2026-10-02")[0]

    assert finding["output_class"] == "OBSERVATION"
    assert finding["priority"] == "P4"


def test_build_report_validates_and_json_is_deterministic() -> None:
    findings = materialize_findings([group()], baseline_as_of="2026-10-02")
    report = build_audit_report(
        audit_id="audit_1",
        mode="standard",
        started_at="2026-10-02T20:00:00Z",
        completed_at="2026-10-02T20:05:00Z",
        baseline_as_of="2026-10-02",
        repository={"full_name": "acme/demo"},
        snapshot={"target_branch": "main", "target_commit_sha": "b" * 40},
        profile={"repository_type": "cli"},
        audit_plan=base_plan(),
        coverage={"snapshot": "VERIFIED", "ci_history": "PARTIAL"},
        control_results=[],
        providers=[],
        findings=findings,
        observations=[],
        blind_spots=[{"domain": "ci_history", "summary": "Only retained history was available."}],
        remediation_tracks=[{
            "id": "track_ci_stabilization",
            "title": "CI Stabilization",
            "finding_ids": [findings[0]["id"]],
            "steps": [{"kind": "STABILIZE_CONTROL", "action": "Stabilize CI.", "finding_ids": [findings[0]["id"]]}],
        }],
    )

    validate_document("audit-report.v1", report)
    first = render_json(report)
    second = render_json(report)
    assert first == second
    assert json.loads(first)["audit"]["baseline_as_of"] == "2026-10-02"


def test_markdown_contains_required_sections_and_bounded_language() -> None:
    findings = materialize_findings([group()], baseline_as_of="2026-10-02")
    report = build_audit_report(
        audit_id="audit_1",
        mode="standard",
        started_at="2026-10-02T20:00:00Z",
        completed_at="2026-10-02T20:05:00Z",
        baseline_as_of="2026-10-02",
        repository={"full_name": "acme/demo"},
        snapshot={"target_branch": "main", "target_commit_sha": "b" * 40},
        profile={},
        audit_plan=base_plan(),
        coverage={"snapshot": "VERIFIED", "ci_history": "PARTIAL"},
        control_results=[],
        providers=[],
        findings=findings,
        observations=[],
        blind_spots=[{"domain": "ci_history", "summary": "Only retained history was available."}],
        remediation_tracks=[{
            "id": "track_ci_stabilization",
            "title": "CI Stabilization",
            "finding_ids": [findings[0]["id"]],
            "steps": [{"kind": "STABILIZE_CONTROL", "action": "Stabilize CI.", "finding_ids": [findings[0]["id"]]}],
        }],
    )

    markdown = render_markdown(report)

    assert "# Repository Assurance Audit" in markdown
    assert "## Assurance Coverage" in markdown
    assert "## Priority Findings" in markdown
    assert "## Remediation Tracks" in markdown
    assert "## Blind Spots" in markdown
    assert "## Technical Appendix" in markdown
    assert "acme/demo" in markdown
    assert "Target SHA" in markdown
    assert "Repository is secure" not in markdown
    assert "No vulnerabilities exist" not in markdown
    assert "/100" not in markdown


def test_priority_findings_are_sorted_by_priority() -> None:
    cleanup = group(finding_type="CLEANUP_CANDIDATE", identifier="feature-old", fingerprint="sha256:" + "c" * 64)
    cleanup["subject"] = {"type": "local_branch", "identifier": "feature-old"}
    cleanup["root_discriminator"] = "integrated-stale-branch"
    cleanup["control_ids"] = ["HYGIENE-001"]
    findings = materialize_findings([cleanup, group()], baseline_as_of="2026-10-02")
    report = build_audit_report(
        audit_id="audit_1", mode="standard",
        started_at="2026-10-02T20:00:00Z", completed_at="2026-10-02T20:05:00Z",
        baseline_as_of="2026-10-02", repository={"full_name": "acme/demo"},
        snapshot={"target_branch": "main", "target_commit_sha": "b" * 40}, profile={},
        audit_plan=base_plan(), coverage={}, control_results=[], providers=[], findings=findings,
        observations=[], blind_spots=[], remediation_tracks=[],
    )

    markdown = render_markdown(report)

    assert markdown.index("P1") < markdown.index("P4")


def test_generic_control_finding_is_visible_in_priority_markdown() -> None:
    generic = group(
        finding_type="CONTROL_FINDING",
        identifier=".github/workflows/ci.yml",
        fingerprint="sha256:" + "d" * 64,
    )
    generic["root_discriminator"] = "control-finding:CI-STATIC-003"
    generic["control_ids"] = ["CI-STATIC-003"]
    generic["proposed_severities"] = ["MEDIUM"]
    generic["proposed_confidences"] = ["HIGH"]

    findings = materialize_findings([generic], baseline_as_of="2026-10-02")
    report = build_audit_report(
        audit_id="audit_1",
        mode="standard",
        started_at="2026-10-02T20:00:00Z",
        completed_at="2026-10-02T20:05:00Z",
        baseline_as_of="2026-10-02",
        repository={"full_name": "acme/demo"},
        snapshot={"target_branch": "main", "target_commit_sha": "b" * 40},
        profile={},
        audit_plan=base_plan(),
        coverage={},
        control_results=[],
        providers=[],
        findings=findings,
        observations=[],
        blind_spots=[],
        remediation_tracks=[],
    )

    markdown = render_markdown(report)

    assert findings[0]["id"] in markdown
    assert "CI-STATIC-003 reported a material finding" in markdown
    assert "CI-STATIC-003" in markdown


def test_operational_and_governance_types_get_specific_titles() -> None:
    cases = [
        ("CHRONIC_FAILURE", "CI workflow is chronically failing"),
        ("FLAKY_JOB", "CI workflow is flaky"),
        ("STALE_REQUIRED_CHECK", "Required status check is stale"),
        ("DEPRECATION_RISK", "Current platform lifecycle creates a deprecation risk"),
    ]
    groups = []
    for index, (finding_type, _) in enumerate(cases):
        item = group(
            finding_type=finding_type,
            identifier=f"subject-{index}",
            fingerprint="sha256:" + format(index + 1, "064x"),
        )
        groups.append(item)

    findings = materialize_findings(groups, baseline_as_of="2026-10-02")
    by_type = {item["type"]: item for item in findings}

    for finding_type, title in cases:
        assert by_type[finding_type]["title"] == title
