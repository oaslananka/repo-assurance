from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "repository-assurance" / "SKILL.md"


def skill_text() -> str:
    return SKILL.read_text(encoding="utf-8")


def test_skill_has_discoverable_frontmatter() -> None:
    text = skill_text()
    assert text.startswith("---\nname: repository-assurance\n")
    assert "description: Use when" in text.split("---", 2)[1]


def test_skill_encodes_core_safety_and_evidence_invariants() -> None:
    text = skill_text()
    required = [
        "read-only",
        "exact audited commit SHA",
        "Unknown is not PASS",
        "Preservation beats cleanup",
        "current authoritative evidence",
        "audit completeness",
    ]
    for phrase in required:
        assert phrase in text


def test_skill_points_to_canonical_cli_without_mutation_workflow() -> None:
    text = skill_text()
    assert "repo-assurance audit" in text
    assert "--fix" not in text
    assert "--apply" not in text
    assert "automatic remediation" not in text.lower()


def test_skill_requires_bounded_claims_instead_of_security_verdicts() -> None:
    text = skill_text()
    assert "No alerts observed" in text
    assert "No vulnerabilities exist" in text
    assert "never report" in text.lower()
