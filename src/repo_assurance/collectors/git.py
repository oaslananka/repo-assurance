from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner


class GitCollectionError(RuntimeError):
    """Raised when required Git state cannot be collected."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run(runner: ReadOnlyCommandRunner, repo: Path, *args: str, required: bool = True) -> str | None:
    result = runner.run(["git", *args], cwd=repo)
    if result.returncode != 0:
        if required:
            raise GitCollectionError(result.stderr.strip() or f"git {' '.join(args)} failed")
        return None
    return result.stdout.strip()


def _github_identity(remote_url: str | None) -> tuple[str | None, str | None, str | None]:
    if not remote_url:
        return None, None, None
    patterns = (
        r"^https?://github\.com/(?P<owner>[^/]+)/(?P<name>[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/(?P<owner>[^/]+)/(?P<name>[^/]+?)(?:\.git)?$",
        r"^git@github\.com:(?P<owner>[^/]+)/(?P<name>[^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.match(pattern, remote_url)
        if match:
            owner = match.group("owner")
            name = match.group("name")
            return owner, name, f"{owner}/{name}"
    return None, None, None


def _evidence(
    *,
    evidence_id: str,
    subject: dict[str, Any],
    observation: dict[str, Any],
    repository: str,
    target_sha: str,
) -> dict[str, Any]:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "git_state",
        "source": {"provider": "git", "mechanism": "cli", "collector": "local-git/v1"},
        "subject": subject,
        "observation": observation,
        "snapshot": {"repository": repository, "target_commit_sha": target_sha},
        "collected_at": _now(),
        "visibility": {
            "completeness": "complete",
            "permission_limited": False,
            "retention_limited": False,
        },
        "redactions": [],
    }


def collect_repository_identity(repo: Path) -> list[dict[str, Any]]:
    runner = ReadOnlyCommandRunner()
    head = _run(runner, repo, "rev-parse", "HEAD")
    root = _run(runner, repo, "rev-parse", "--show-toplevel")
    remote_url = _run(runner, repo, "config", "--get", "remote.origin.url", required=False)
    owner, name, full_name = _github_identity(remote_url)
    repository_id = full_name or str(root)
    subject = {"type": "repository", "identifier": repository_id}
    observation = {
        "remote_name": "origin" if remote_url else None,
        "remote_url": remote_url,
        "owner": owner,
        "name": name,
        "full_name": full_name,
        "git_root": str(root),
    }
    return [
        _evidence(
            evidence_id="ev_git_identity",
            subject=subject,
            observation=observation,
            repository=repository_id,
            target_sha=str(head),
        )
    ]


def _resolve_remote_tracking(
    runner: ReadOnlyCommandRunner,
    repo: Path,
    branch: str,
) -> tuple[str | None, str | None]:
    upstream = _run(
        runner,
        repo,
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{u}",
        required=False,
    )
    if upstream:
        sha = _run(runner, repo, "rev-parse", upstream, required=False)
        return upstream, sha
    if branch:
        fallback = f"refs/remotes/origin/{branch}"
        sha = _run(runner, repo, "rev-parse", "--verify", fallback, required=False)
        if sha:
            return f"origin/{branch}", sha
    return None, None


def _classify_drift(
    runner: ReadOnlyCommandRunner,
    repo: Path,
    *,
    head: str,
    branch: str,
    remote_sha: str | None,
) -> str:
    if not branch:
        return "DETACHED"
    if not remote_sha:
        return "UNKNOWN"
    if head == remote_sha:
        return "IN_SYNC"
    remote_is_ancestor = runner.run(["git", "merge-base", "--is-ancestor", remote_sha, head], cwd=repo)
    if remote_is_ancestor.returncode == 0:
        return "LOCAL_AHEAD"
    local_is_ancestor = runner.run(["git", "merge-base", "--is-ancestor", head, remote_sha], cwd=repo)
    if local_is_ancestor.returncode == 0:
        return "LOCAL_BEHIND"
    return "DIVERGED"


def _workspace_counts(status: str) -> dict[str, Any]:
    staged = 0
    unstaged = 0
    untracked = 0
    for line in status.splitlines():
        if not line:
            continue
        if line.startswith("??"):
            untracked += 1
            continue
        if len(line) >= 2:
            if line[0] not in {" ", "?", "!"}:
                staged += 1
            if line[1] not in {" ", "?", "!"}:
                unstaged += 1
    return {
        "dirty": bool(staged or unstaged or untracked),
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
    }


def collect_snapshot(repo: Path, target_ref: str | None) -> list[dict[str, Any]]:
    runner = ReadOnlyCommandRunner()
    head = str(_run(runner, repo, "rev-parse", "HEAD"))
    branch = str(_run(runner, repo, "branch", "--show-current") or "")
    target = target_ref or branch or "HEAD"
    target_sha = str(_run(runner, repo, "rev-parse", target))
    upstream, remote_sha = _resolve_remote_tracking(runner, repo, branch)
    drift = _classify_drift(runner, repo, head=head, branch=branch, remote_sha=remote_sha)
    status = str(_run(runner, repo, "status", "--porcelain=v1") or "")
    workspace = _workspace_counts(status)
    repository = str(_run(runner, repo, "rev-parse", "--show-toplevel"))
    subject = {"type": "repository", "identifier": repository}

    return [
        _evidence(
            evidence_id="ev_git_snapshot",
            subject=subject,
            observation={
                "head_sha": head,
                "branch": branch or None,
                "detached": not bool(branch),
                "target_ref": target,
                "target_commit_sha": target_sha,
                "upstream": upstream,
                "remote_tracking_sha": remote_sha,
                "drift": drift,
            },
            repository=repository,
            target_sha=target_sha,
        ),
        _evidence(
            evidence_id="ev_git_workspace",
            subject=subject,
            observation=workspace,
            repository=repository,
            target_sha=target_sha,
        ),
    ]
