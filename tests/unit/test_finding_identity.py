from __future__ import annotations

from repo_assurance.core.dedupe import deduplicate_candidates
from repo_assurance.core.fingerprints import build_finding_fingerprint


def candidate(
    candidate_id: str,
    *,
    control_id: str = "CI-OPS-006",
    subject: dict | None = None,
    finding_type: str = "UNRELIABLE_GATE",
    evidence_ids: list[str] | None = None,
    root: str = "required-unreliable-gate",
    severity: str = "HIGH",
    confidence: str = "CONFIRMED",
) -> dict:
    return {
        "schema_version": "candidate-finding/v1",
        "candidate_id": candidate_id,
        "control_id": control_id,
        "subject": subject or {"type": "github_workflow", "identifier": ".github/workflows/ci.yml"},
        "type": finding_type,
        "evidence_ids": evidence_ids or ["ev_1"],
        "proposed_severity": severity,
        "proposed_confidence": confidence,
        "root_discriminator": root,
    }


def test_fingerprint_is_deterministic_for_same_semantic_input() -> None:
    subject = {
        "type": "github_workflow",
        "identifier": ".github\\workflows\\ci.yml",
        "qualifiers": {"z": "last", "a": "first"},
    }

    first = build_finding_fingerprint(
        control_family="CI-OPS",
        subject=subject,
        root_discriminator="required-unreliable-gate",
    )
    second = build_finding_fingerprint(
        control_family="CI-OPS",
        subject={
            "qualifiers": {"a": "first", "z": "last"},
            "identifier": ".github/workflows/ci.yml",
            "type": "github_workflow",
        },
        root_discriminator="required-unreliable-gate",
    )

    assert first == second
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64


def test_dedup_is_invariant_to_evidence_and_candidate_order() -> None:
    a = candidate("candidate_a", evidence_ids=["ev_2", "ev_1"])
    b = candidate("candidate_b", evidence_ids=["ev_3"])

    first = deduplicate_candidates([a, b])
    second = deduplicate_candidates([b, a])

    assert first == second
    assert len(first) == 1
    assert first[0]["candidate_ids"] == ["candidate_a", "candidate_b"]
    assert first[0]["evidence_ids"] == ["ev_1", "ev_2", "ev_3"]


def test_same_issue_from_multiple_controls_merges_but_preserves_sources() -> None:
    first = candidate("candidate_ops", control_id="CI-OPS-006", evidence_ids=["ev_history"])
    second = candidate("candidate_policy", control_id="GH-GOV-003", evidence_ids=["ev_rules"], severity="MEDIUM", confidence="HIGH")

    groups = deduplicate_candidates([first, second])

    assert len(groups) == 1
    assert groups[0]["control_ids"] == ["CI-OPS-006", "GH-GOV-003"]
    assert groups[0]["evidence_ids"] == ["ev_history", "ev_rules"]
    assert groups[0]["proposed_severities"] == ["HIGH", "MEDIUM"]
    assert groups[0]["proposed_confidences"] == ["CONFIRMED", "HIGH"]


def test_different_root_issue_remains_separate() -> None:
    chronic = candidate("candidate_chronic", root="required-unreliable-gate")
    stale = candidate("candidate_stale", root="stale-required-check")

    groups = deduplicate_candidates([chronic, stale])

    assert len(groups) == 2
    assert {group["root_discriminator"] for group in groups} == {
        "required-unreliable-gate",
        "stale-required-check",
    }


def test_different_finding_types_do_not_merge_even_with_same_root() -> None:
    unreliable = candidate("candidate_a", finding_type="UNRELIABLE_GATE")
    preservation = candidate("candidate_b", finding_type="PRESERVATION_RISK")

    groups = deduplicate_candidates([unreliable, preservation])

    assert len(groups) == 2
