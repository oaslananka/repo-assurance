from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "skills" / "repository-assurance" / "SKILL.md"
CLAUDE_SKILL = ROOT / ".claude" / "skills" / "repository-assurance" / "SKILL.md"
OPENCODE_SKILL = ROOT / ".opencode" / "skills" / "repository-assurance" / "SKILL.md"
AGENTS = ROOT / "AGENTS.md"
ROOT_SKILL = ROOT / "SKILL.md"
OPENCODE_CONFIG = ROOT / "opencode.json"


def test_canonical_skill_declares_cli_mcp_partial_execution_order() -> None:
    text = CANONICAL.read_text(encoding="utf-8")

    assert "CLI-first" in text
    assert "MCP-second" in text
    assert "skill-only fallback" in text
    assert "repo-assurance audit --repo <path> --mode standard" in text
    assert "PARTIAL_SKILL_GUIDED_AUDIT" in text
    assert "Canonical `QUICK`, `STANDARD`, or `DEEP`" in text
    assert "actually executed" in text


def test_canonical_skill_preserves_cross_agent_safety_invariants() -> None:
    text = CANONICAL.read_text(encoding="utf-8")

    required = [
        "read-only",
        "exact audited commit SHA",
        "Unknown is not PASS",
        "Preservation beats cleanup",
        "current authoritative evidence",
    ]
    for phrase in required:
        assert phrase in text


def test_claude_and_opencode_generated_skills_match_canonical_source() -> None:
    expected = CANONICAL.read_bytes()

    assert CLAUDE_SKILL.is_file()
    assert OPENCODE_SKILL.is_file()
    assert CLAUDE_SKILL.read_bytes() == expected
    assert OPENCODE_SKILL.read_bytes() == expected



def test_opencode_config_registers_generated_skill_directory() -> None:
    import json

    payload = json.loads(OPENCODE_CONFIG.read_text(encoding="utf-8"))
    assert payload["skills"]["paths"] == [".opencode/skills"]

def test_repo_agent_instructions_point_to_canonical_skill_and_execution_order() -> None:
    text = AGENTS.read_text(encoding="utf-8")

    assert "skills/repository-assurance/SKILL.md" in text
    assert "CLI-first" in text
    assert "MCP-second" in text
    assert "PARTIAL_SKILL_GUIDED_AUDIT" in text
    assert "Unknown != PASS" in text
    assert "Preservation beats cleanup" in text
    assert "read-only applies to audit execution" in text
    assert "explicitly requested development work may edit" in text



def test_root_wrapper_description_matches_canonical_skill() -> None:
    canonical_description = next(
        line
        for line in CANONICAL.read_text(encoding="utf-8").splitlines()
        if line.startswith("description: ")
    )
    root_description = next(
        line
        for line in ROOT_SKILL.read_text(encoding="utf-8").splitlines()
        if line.startswith("description: ")
    )
    assert root_description == canonical_description

def test_root_skill_is_thin_compatibility_wrapper() -> None:
    text = ROOT_SKILL.read_text(encoding="utf-8")

    assert "skills/repository-assurance/SKILL.md" in text
    assert "canonical skill source" in text.lower()
    assert "Do not duplicate the audit methodology here." in text


def test_agent_asset_sync_check_passes() -> None:
    spec = importlib.util.spec_from_file_location(
        "sync_agent_assets",
        ROOT / "scripts" / "sync_agent_assets.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.drifted_assets() == []

