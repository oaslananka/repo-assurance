from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repo_assurance.cli import main
from repo_assurance.core.schema import validate_document


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def init_acceptance_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "self-audit-fixture"
    repo.mkdir()
    git(repo, "init")
    git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")

    (repo / "app.py").write_text("print('target')\n", encoding="utf-8")
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """name: CI
on:
  push:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: python app.py
""",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "audited target")
    target_sha = git(repo, "rev-parse", "HEAD")
    git(repo, "remote", "add", "origin", "https://github.com/acme/demo.git")
    git(repo, "update-ref", "refs/remotes/origin/main", target_sha)

    (repo / "app.py").write_text("print('later')\n", encoding="utf-8")
    workflow.write_text(
        """name: LATER
on:
  push:
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python app.py
""",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "later checkout")
    workflow.write_text("name: DIRTY\n", encoding="utf-8")

    return repo, target_sha


def test_canonical_offline_self_audit_acceptance(tmp_path: Path) -> None:
    repo, target_sha = init_acceptance_repo(tmp_path)
    output = tmp_path / "acceptance-output"

    before_head = git(repo, "rev-parse", "HEAD")
    before_status = git(repo, "status", "--porcelain=v1")
    before_refs = git(repo, "for-each-ref", "--format=%(refname) %(objectname)")

    assert main([
        "audit",
        "--repo",
        str(repo),
        "--target",
        target_sha,
        "--mode",
        "standard",
        "--offline",
        "--no-current-baseline",
        "--debug-evidence",
        "--output",
        str(output),
    ]) == 0

    report = json.loads((output / "audit-report.json").read_text(encoding="utf-8"))
    plan = json.loads((output / "audit-plan.json").read_text(encoding="utf-8"))
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    markdown = (output / "audit-report.md").read_text(encoding="utf-8")

    validate_document("audit-plan.v1", plan)
    validate_document("audit-report.v1", report)

    assert report["snapshot"]["target_commit_sha"] == target_sha
    workflow = next(
        item
        for item in evidence
        if item.get("source", {}).get("collector") == "workflow-source/v1"
    )
    assert workflow["snapshot"]["target_commit_sha"] == target_sha
    assert "permissions: write-all" in workflow["observation"]["text"]
    assert "name: LATER" not in workflow["observation"]["text"]
    assert "name: DIRTY" not in workflow["observation"]["text"]

    permission_result = next(
        item
        for item in report["control_results"]
        if item["control_id"] == "CI-STATIC-003"
    )
    assert permission_result["state"] == "FINDING"
    canonical = next(
        item
        for item in report["findings"]
        if "CI-STATIC-003" in item.get("control_ids", [])
    )
    assert canonical["output_class"] == "FINDING"
    assert canonical["evidence_ids"]

    assert report["coverage"]["github_governance"] == "UNAVAILABLE"
    assert report["coverage"]["ci_history"] == "UNAVAILABLE"
    assert report["coverage"]["github_security"] == "UNAVAILABLE"
    assert report["coverage"]["dependencies"] == "UNAVAILABLE"
    assert report["coverage"]["external_providers"] == "UNAVAILABLE"

    assert "# Repository Assurance Audit" in markdown
    assert "## Assurance Coverage" in markdown
    assert "## External Providers" in markdown
    assert "## Priority Findings" in markdown
    assert "## Blind Spots" in markdown
    assert canonical["id"] in markdown
    assert canonical["title"] in markdown
    assert "No vulnerabilities exist" not in markdown
    assert "Repository is secure" not in markdown

    assert git(repo, "rev-parse", "HEAD") == before_head
    assert git(repo, "status", "--porcelain=v1") == before_status
    assert git(repo, "for-each-ref", "--format=%(refname) %(objectname)") == before_refs
