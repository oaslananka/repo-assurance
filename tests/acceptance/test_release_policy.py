from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
PLUGIN = ROOT / "plugin.json"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
LICENSE = ROOT / "LICENSE"
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
    assert "--only-binary=:all:" in workflow
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


def test_public_distribution_metadata_uses_mit_license() -> None:
    package = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    license_text = LICENSE.read_text(encoding="utf-8")

    assert package["project"]["license"] == "MIT"
    assert "LICENSE" in package["project"]["license-files"]
    assert license_text.startswith("MIT License\n")
    assert "Permission is hereby granted, free of charge" in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
    assert "MIT License" in readme


def test_publish_workflow_reuses_validated_artifacts() -> None:
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "validation_run_id" in workflow
    assert "expected_tag" in workflow
    assert "target" in workflow
    assert "actions: read" in workflow
    assert "contents: write" in workflow
    assert "id-token: write" in workflow
    assert "gh run download" in workflow
    assert '--repo "$GITHUB_REPOSITORY"' in workflow
    assert "release-manifest.json" in workflow
    assert "sha256sum --check SHA256SUMS" in workflow
    assert "python scripts/build_release.py" not in workflow
    assert "gh release create" in workflow
    github_release_step = workflow.split(
        "- name: Create GitHub Release from validated artifacts", 1
    )[1]
    assert 'GH_REPO: ${{ github.repository }}' in github_release_step
    assert '--repo "$GITHUB_REPOSITORY"' in github_release_step
    assert "gh release download" in github_release_step
    assert "Existing GitHub Release matches validated artifact set" in github_release_step
    assert (
        "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
        in workflow
    )
    assert "environment:" in workflow
    assert "name: testpypi" in workflow
    assert "name: pypi" in workflow
    assert "https://test.pypi.org/legacy/" in workflow
    assert "- testpypi" in workflow
    assert "- production" in workflow
    assert "concurrency:" in workflow
    assert "cancel-in-progress: false" in workflow
    assert workflow.count("attestations: true") == 2
    assert "scripts/verify_pypi_release.py" in workflow
    assert workflow.count("--only-binary=:all: --require-hashes -r requirements/ci.lock") == 3
    assert "--no-index --no-deps" not in workflow
    assert workflow.count('PYTHONPATH="$WHEEL" VERSION="$VERSION" python') == 3
    assert workflow.count("from repo_assurance.cli import build_parser") == 3
    assert workflow.count("repo_assurance-*.whl") >= 5
    assert "jsonschema>=4.23,<5" not in workflow
    assert "repo-assurance==$VERSION" not in workflow
    assert "repo-assurance --help" not in workflow
