from __future__ import annotations

from repo_assurance.core.remediation import build_remediation_tracks


def finding(
    finding_id: str,
    finding_type: str,
    *,
    subject: str = ".github/workflows/ci.yml",
    subject_type: str = "github_workflow",
    priority: str = "P1",
) -> dict:
    return {
        "id": finding_id,
        "type": finding_type,
        "priority": priority,
        "subject": {"type": subject_type, "identifier": subject},
    }


def track(tracks: list[dict], title: str) -> dict:
    return next(item for item in tracks if item["title"] == title)


def test_ci_stabilization_precedes_enforcement() -> None:
    findings = [
        finding("F-UNRELIABLE", "UNRELIABLE_GATE"),
        finding("F-ENFORCE", "ENFORCEMENT_GAP"),
    ]

    tracks = build_remediation_tracks(findings)
    ci = track(tracks, "CI Stabilization")

    assert [step["kind"] for step in ci["steps"]] == [
        "STABILIZE_CONTROL",
        "VERIFY_STABILITY",
        "ENFORCE_CONTROL",
    ]
    assert ci["steps"][2]["blocked_by"] == ["F-UNRELIABLE"]


def test_preservation_risk_suppresses_cleanup_recommendation_for_same_subject() -> None:
    findings = [
        finding("F-PRESERVE", "PRESERVATION_RISK", subject="feature-old", subject_type="local_branch"),
        finding("F-CLEAN", "CLEANUP_CANDIDATE", subject="feature-old", subject_type="local_branch", priority="P4"),
    ]

    tracks = build_remediation_tracks(findings)
    hygiene = track(tracks, "Repository Hygiene")

    assert [step["kind"] for step in hygiene["steps"]] == ["PRESERVE_WORK"]
    assert hygiene["finding_ids"] == ["F-PRESERVE"]


def test_cleanup_candidate_without_preservation_risk_is_kept() -> None:
    tracks = build_remediation_tracks([
        finding("F-CLEAN", "CLEANUP_CANDIDATE", subject="feature-old", subject_type="local_branch", priority="P4")
    ])

    hygiene = track(tracks, "Repository Hygiene")
    assert [step["kind"] for step in hygiene["steps"]] == ["REVIEW_CLEANUP"]


def test_governance_and_modernization_get_separate_tracks() -> None:
    tracks = build_remediation_tracks([
        finding("F-GOV", "ENFORCEMENT_GAP"),
        finding("F-RUNNER", "DEPRECATION_RISK", subject="macos-14", subject_type="runtime", priority="P2"),
    ])

    assert [item["title"] for item in tracks] == [
        "GitHub Governance",
        "Current Platform Modernization",
    ]


def test_track_finding_ids_and_steps_are_deterministic() -> None:
    findings = [
        finding("F-B", "STALE_CONTROL", subject="nightly"),
        finding("F-A", "STALE_CONTROL", subject="ci"),
    ]

    first = build_remediation_tracks(findings)
    second = build_remediation_tracks(list(reversed(findings)))

    assert first == second
