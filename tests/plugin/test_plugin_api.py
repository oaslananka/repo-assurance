from __future__ import annotations

import subprocess
from pathlib import Path

from repo_assurance.plugin.api import (
    audit_repository,
    discover_repository,
    plan_repository_audit,
    render_audit_report,
)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "demo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial")
    return repo


def test_discover_repository_returns_stable_snapshot(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    result = discover_repository(str(repo))
    assert result["repository"]["full_name"] == "local/demo"
    assert result["snapshot"]["target_commit_sha"] == git(repo, "rev-parse", "HEAD")
    assert result["profile"]["repository_type"] == "documentation"


def test_plan_repository_audit_accounts_for_catalog(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    plan = plan_repository_audit(str(repo), mode="quick")
    assert plan["mode"] == "quick"
    assert plan["controls"]
    assert all("control_id" in entry and "applicable" in entry for entry in plan["controls"])


def test_audit_repository_offline_is_canonical_and_read_only(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    before_head = git(repo, "rev-parse", "HEAD")
    before_status = git(repo, "status", "--porcelain=v1")

    result = audit_repository(str(repo), mode="quick", offline=True)

    assert result["report"]["schema_version"] == "audit-report/v1"
    assert result["report"]["snapshot"]["target_commit_sha"] == before_head
    assert result["evidence_count"] >= 1
    assert "evidence" not in result
    assert git(repo, "rev-parse", "HEAD") == before_head
    assert git(repo, "status", "--porcelain=v1") == before_status


def test_render_audit_report_accepts_canonical_report(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    report = audit_repository(str(repo), mode="quick", offline=True)["report"]
    markdown = render_audit_report(report, format="markdown")
    assert markdown.startswith("# Repository Assurance Audit")
    json_text = render_audit_report(report, format="json")
    assert '"schema_version": "audit-report/v1"' in json_text
