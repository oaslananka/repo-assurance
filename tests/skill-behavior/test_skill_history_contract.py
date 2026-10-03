from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "repository-assurance" / "SKILL.md"


def skill_text() -> str:
    return SKILL.read_text(encoding="utf-8")


def test_skill_allows_bounded_ci_history_across_commits() -> None:
    text = skill_text()
    assert "Historical CI evidence may span commits by design." in text
    assert "preserving each run's `head_sha`" in text
    assert "mixed-configuration" in text


def test_deleted_remote_ref_alone_is_not_a_preservation_finding() -> None:
    text = skill_text()
    assert "A deleted remote branch is not itself a preservation finding." in text
    assert "HYGIENE-004" in text
    assert "observation only" in text


def test_skill_only_audits_have_explicit_noncanonical_provenance() -> None:
    text = skill_text()
    assert "PARTIAL_SKILL_GUIDED_AUDIT" in text
    assert "advisory candidates" in text
