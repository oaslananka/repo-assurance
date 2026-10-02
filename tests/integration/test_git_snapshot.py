from __future__ import annotations

import subprocess
from pathlib import Path

from repo_assurance.collectors.git import collect_repository_identity, collect_snapshot
from repo_assurance.evaluators.snapshot import evaluate_snapshot


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("one\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial")
    git(repo, "remote", "add", "origin", "https://github.com/acme/demo.git")
    git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "HEAD"))
    return repo


def snapshot_observation(evidence: list[dict]) -> dict:
    return next(item["observation"] for item in evidence if item["id"] == "ev_git_snapshot")


def workspace_observation(evidence: list[dict]) -> dict:
    return next(item["observation"] for item in evidence if item["id"] == "ev_git_workspace")


def test_collect_repository_identity_parses_github_remote(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    evidence = collect_repository_identity(repo)
    observation = evidence[0]["observation"]
    assert observation["owner"] == "acme"
    assert observation["name"] == "demo"
    assert observation["full_name"] == "acme/demo"
    assert observation["remote_name"] == "origin"


def test_clean_repository_is_in_sync(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    evidence = collect_snapshot(repo, "main")
    observation = snapshot_observation(evidence)
    assert observation["drift"] == "IN_SYNC"
    assert observation["target_commit_sha"] == git(repo, "rev-parse", "main")
    assert workspace_observation(evidence) == {
        "dirty": False, "staged": 0, "unstaged": 0, "untracked": 0
    }


def test_local_ahead_is_classified(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "README.md").write_text("two\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "local ahead")
    evidence = collect_snapshot(repo, "main")
    assert snapshot_observation(evidence)["drift"] == "LOCAL_AHEAD"


def test_local_behind_is_classified(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    first = git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("remote two\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "remote ahead")
    remote = git(repo, "rev-parse", "HEAD")
    git(repo, "reset", "--hard", first)
    git(repo, "update-ref", "refs/remotes/origin/main", remote)
    evidence = collect_snapshot(repo, "main")
    assert snapshot_observation(evidence)["drift"] == "LOCAL_BEHIND"


def test_diverged_is_classified(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-b", "remote-side")
    (repo / "remote.txt").write_text("remote\n", encoding="utf-8")
    git(repo, "add", "remote.txt")
    git(repo, "commit", "-m", "remote side")
    remote = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "main")
    git(repo, "reset", "--hard", base)
    (repo / "local.txt").write_text("local\n", encoding="utf-8")
    git(repo, "add", "local.txt")
    git(repo, "commit", "-m", "local side")
    git(repo, "update-ref", "refs/remotes/origin/main", remote)
    evidence = collect_snapshot(repo, "main")
    assert snapshot_observation(evidence)["drift"] == "DIVERGED"


def test_detached_head_is_classified(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    git(repo, "checkout", "--detach", "HEAD")
    evidence = collect_snapshot(repo, "HEAD")
    assert snapshot_observation(evidence)["drift"] == "DETACHED"


def test_dirty_workspace_counts_staged_unstaged_and_untracked(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "README.md").write_text("staged\n", encoding="utf-8")
    git(repo, "add", "README.md")
    (repo / "README.md").write_text("unstaged after staged\n", encoding="utf-8")
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    evidence = collect_snapshot(repo, "main")
    assert workspace_observation(evidence) == {
        "dirty": True, "staged": 1, "unstaged": 1, "untracked": 1
    }


def test_snapshot_collection_does_not_change_repository_state(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "new.txt").write_text("preserve me\n", encoding="utf-8")
    before_head = git(repo, "rev-parse", "HEAD")
    before_status = git(repo, "status", "--porcelain=v1")
    before_branch = git(repo, "branch", "--show-current")
    collect_snapshot(repo, "main")
    assert git(repo, "rev-parse", "HEAD") == before_head
    assert git(repo, "status", "--porcelain=v1") == before_status
    assert git(repo, "branch", "--show-current") == before_branch


def test_snapshot_evaluator_accounts_for_all_snapshot_controls(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    evidence = collect_repository_identity(repo) + collect_snapshot(repo, "main")
    results = evaluate_snapshot(evidence)
    assert {item["control_id"] for item in results} == {
        "SNAP-001", "SNAP-002", "SNAP-003", "SNAP-004"
    }
    assert all(item["state"] == "PASS" for item in results)
