from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from repo_assurance.collectors.git import collect_branches, collect_stashes, collect_worktrees
from repo_assurance.evaluators.hygiene import evaluate_hygiene

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
OLD_DATE = "2025-01-01T12:00:00+00:00"


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        ["git", *args], cwd=repo, env=merged_env, text=True,
        capture_output=True, check=True,
    )
    return result.stdout.strip()


def commit(repo: Path, message: str, filename: str, content: str, *, date: str | None = None) -> str:
    (repo / filename).write_text(content, encoding="utf-8")
    git(repo, "add", filename)
    env = None
    if date:
        env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    git(repo, "commit", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD")


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")
    commit(repo, "initial", "README.md", "initial\n", date=OLD_DATE)
    git(repo, "remote", "add", "origin", "https://github.com/acme/demo.git")
    git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "main"))
    return repo


def track_branch(repo: Path, branch: str) -> None:
    sha = git(repo, "rev-parse", branch)
    git(repo, "update-ref", f"refs/remotes/origin/{branch}", sha)
    git(repo, "config", f"branch.{branch}.remote", "origin")
    git(repo, "config", f"branch.{branch}.merge", f"refs/heads/{branch}")


def by_control(results: list[dict], control_id: str) -> list[dict]:
    return [item for item in results if item["control_id"] == control_id]


def test_old_integrated_branch_is_cleanup_candidate(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "checkout", "-b", "feature-old")
    commit(repo, "old feature", "feature.txt", "done\n", date=OLD_DATE)
    track_branch(repo, "feature-old")
    git(repo, "checkout", "main")
    git(repo, "merge", "--no-ff", "feature-old", "-m", "merge old feature")

    evidence = collect_branches(repo, target_ref="main") + collect_worktrees(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW, stale_after_days=90)

    items = by_control(results, "HYGIENE-001")
    assert any(item["state"] == "FINDING" and item["reason"] == "cleanup_candidate:feature-old" for item in items)


def test_old_branch_with_unique_commits_is_never_cleanup_candidate(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "checkout", "-b", "feature-unique")
    commit(repo, "unique work", "unique.txt", "important\n", date=OLD_DATE)
    track_branch(repo, "feature-unique")
    git(repo, "checkout", "main")

    evidence = collect_branches(repo, target_ref="main") + collect_worktrees(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW, stale_after_days=90)

    assert not any(
        item.get("reason") == "cleanup_candidate:feature-unique"
        for item in by_control(results, "HYGIENE-001")
    )


def test_remote_deleted_local_branch_with_unique_commits_is_preservation_risk(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "checkout", "-b", "feature-gone")
    commit(repo, "unique local", "lost.txt", "preserve\n", date=OLD_DATE)
    track_branch(repo, "feature-gone")
    git(repo, "update-ref", "-d", "refs/remotes/origin/feature-gone")
    git(repo, "checkout", "main")

    evidence = collect_branches(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW)

    item = next(item for item in by_control(results, "HYGIENE-004") if item["state"] == "FINDING")
    assert item["reason"] == "preservation_risk:feature-gone:remote_deleted_local_unique_work"
    meta = next(item for item in by_control(results, "HYGIENE-010") if item["state"] == "FINDING")
    assert "feature-gone" in meta["reason"]


def test_dirty_secondary_worktree_is_preserve_first(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "branch", "worktree-branch")
    worktree = tmp_path / "secondary"
    git(repo, "worktree", "add", str(worktree), "worktree-branch")
    (worktree / "draft.txt").write_text("untracked work\n", encoding="utf-8")

    evidence = collect_branches(repo, target_ref="main") + collect_worktrees(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW)

    item = next(item for item in by_control(results, "HYGIENE-005") if item["state"] == "FINDING")
    assert item["reason"].startswith("preserve_first:dirty_worktree:")


def test_dirty_worktree_overrides_integrated_branch_cleanup(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "branch", "old-cleanup")
    track_branch(repo, "old-cleanup")
    worktree = tmp_path / "secondary"
    git(repo, "worktree", "add", str(worktree), "old-cleanup")
    (worktree / "draft.txt").write_text("do not lose\n", encoding="utf-8")

    evidence = collect_branches(repo, target_ref="main") + collect_worktrees(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW, stale_after_days=90)

    assert not any(
        item.get("reason") == "cleanup_candidate:old-cleanup"
        for item in by_control(results, "HYGIENE-001")
    )
    assert any(
        item["state"] == "FINDING" and "dirty_worktree" in item.get("reason", "")
        for item in by_control(results, "HYGIENE-005")
    )


def test_detached_head_unique_commit_is_preservation_risk(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "checkout", "--detach", "HEAD")
    commit(repo, "detached work", "detached.txt", "unique\n", date=OLD_DATE)

    evidence = collect_branches(repo, target_ref="main")
    results = evaluate_hygiene(evidence, default_branch="main", now=NOW)

    item = next(item for item in by_control(results, "HYGIENE-008") if item["state"] == "FINDING")
    assert item["reason"].startswith("preservation_risk:detached_head_unique_commits:")


def test_stashes_are_collected_without_modifying_them(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "README.md").write_text("stashed\n", encoding="utf-8")
    git(repo, "stash", "push", "-m", "keep-me")
    before = git(repo, "stash", "list")

    evidence = collect_stashes(repo, target_ref="main")

    assert len(evidence) == 1
    assert evidence[0]["subject"]["type"] == "stash"
    assert "keep-me" in evidence[0]["observation"]["message"]
    assert git(repo, "stash", "list") == before
