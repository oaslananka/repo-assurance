from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
PLUGIN = ROOT / "plugin.json"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
POLICY = ROOT / "references" / "release-policy.md"
CHECKLIST = ROOT / "references" / "release-checklist.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def test_python_and_plugin_share_canonical_release_version() -> None:
    package = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    plugin = json.loads(PLUGIN.read_text(encoding="utf-8"))

    version = package["project"]["version"]
    assert plugin["version"] == version
    assert re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
        version,
    )


def test_release_policy_checklist_and_changelog_exist() -> None:
    policy = POLICY.read_text(encoding="utf-8")
    checklist = CHECKLIST.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")

    assert "Semantic Versioning" in policy
    assert "Python package" in policy
    assert "plugin" in policy.lower()
    assert "skill" in policy.lower()
    assert "exact commit" in policy.lower()
    assert "non-publishing" in policy.lower()
    assert "explicit authorization" in policy.lower()
    assert "SHA256SUMS" in policy
    assert "release-manifest.json" in policy
    assert "vX.Y.Z" in checklist
    assert "[Unreleased]" in changelog


def test_release_workflow_is_tagged_sha_pinned_and_nonpublishing() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'tags:' in workflow
    assert '"v*"' in workflow
    assert "workflow_dispatch:" in workflow
    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "fetch-depth: 0" in workflow
    assert "python scripts/build_release.py" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "dist/release" in workflow
    assert "pypi" not in workflow.lower()
    assert "twine" not in workflow.lower()
    assert "gh release create" not in workflow.lower()
    assert "contents: write" not in workflow.lower()


def test_release_builder_and_skill_builder_are_present() -> None:
    release_script = (ROOT / "scripts" / "build_release.py").read_text(encoding="utf-8")
    skill_script = (ROOT / "scripts" / "build_skill.py").read_text(encoding="utf-8")

    assert "release-manifest.json" in release_script
    assert "SHA256SUMS" in release_script
    assert "--expected-tag" in release_script
    assert "git_commit" in release_script
    assert "repository-assurance-skill-" in release_script
    assert "repository-assurance/SKILL.md" in skill_script
