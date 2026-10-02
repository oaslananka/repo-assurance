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


def _int_output(
    runner: ReadOnlyCommandRunner,
    repo: Path,
    *args: str,
) -> int:
    value = _run(runner, repo, *args)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise GitCollectionError(f"git {' '.join(args)} did not return an integer") from exc


def _reachability_state(
    runner: ReadOnlyCommandRunner,
    repo: Path,
    *,
    target_ref: str,
    branch_ref: str,
) -> tuple[str, int, int]:
    ahead = _int_output(runner, repo, "rev-list", "--count", f"{target_ref}..{branch_ref}")
    behind = _int_output(runner, repo, "rev-list", "--count", f"{branch_ref}..{target_ref}")
    if ahead == 0:
        return "FULLY_INTEGRATED", ahead, behind
    if ahead > 0 and behind > 0:
        return "DIVERGED", ahead, behind
    return "HAS_UNIQUE_WORK", ahead, behind


def collect_branches(repo: Path, target_ref: str) -> list[dict[str, Any]]:
    """Collect local branch reachability and detached-head preservation signals."""
    runner = ReadOnlyCommandRunner()
    repository = str(_run(runner, repo, "rev-parse", "--show-toplevel"))
    target_sha = str(_run(runner, repo, "rev-parse", target_ref))
    format_string = "%00".join(
        (
            "%(refname:short)",
            "%(objectname)",
            "%(upstream:short)",
            "%(upstream:track)",
            "%(committerdate:iso8601-strict)",
        )
    )
    listing = str(
        _run(
            runner,
            repo,
            "for-each-ref",
            f"--format={format_string}",
            "refs/heads",
        )
        or ""
    )
    evidence: list[dict[str, Any]] = []

    for index, line in enumerate(listing.splitlines()):
        if not line:
            continue
        parts = line.split("\x00")
        if len(parts) != 5:
            continue
        name, sha, upstream, upstream_track, last_commit_at = parts
        integration_state, ahead, behind = _reachability_state(
            runner,
            repo,
            target_ref=target_ref,
            branch_ref=name,
        )
        evidence.append(
            _evidence(
                evidence_id=f"ev_git_branch_{index}",
                subject={"type": "local_branch", "identifier": name},
                observation={
                    "name": name,
                    "sha": sha,
                    "upstream": upstream or None,
                    "upstream_gone": "gone" in upstream_track.lower(),
                    "last_commit_at": last_commit_at or None,
                    "ahead_of_target": ahead,
                    "behind_target": behind,
                    "integration_state": integration_state,
                    "target_ref": target_ref,
                },
                repository=repository,
                target_sha=target_sha,
            )
        )

    current_branch = str(_run(runner, repo, "branch", "--show-current") or "")
    if not current_branch:
        head = str(_run(runner, repo, "rev-parse", "HEAD"))
        integration_state, ahead, behind = _reachability_state(
            runner,
            repo,
            target_ref=target_ref,
            branch_ref="HEAD",
        )
        evidence.append(
            _evidence(
                evidence_id="ev_git_detached_head",
                subject={"type": "commit", "identifier": head},
                observation={
                    "detached": True,
                    "sha": head,
                    "ahead_of_target": ahead,
                    "behind_target": behind,
                    "integration_state": integration_state,
                    "target_ref": target_ref,
                },
                repository=repository,
                target_sha=target_sha,
            )
        )
    return evidence


def _parse_worktree_blocks(raw: str) -> list[dict[str, str | bool]]:
    blocks: list[dict[str, str | bool]] = []
    current: dict[str, str | bool] = {}
    for line in raw.splitlines() + [""]:
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key in {"detached", "bare"}:
            current[key] = True
        else:
            current[key] = value
    return blocks


def collect_worktrees(repo: Path, target_ref: str) -> list[dict[str, Any]]:
    runner = ReadOnlyCommandRunner()
    repository = str(_run(runner, repo, "rev-parse", "--show-toplevel"))
    target_sha = str(_run(runner, repo, "rev-parse", target_ref))
    raw = str(_run(runner, repo, "worktree", "list", "--porcelain") or "")
    evidence: list[dict[str, Any]] = []

    for index, block in enumerate(_parse_worktree_blocks(raw)):
        path_text = str(block.get("worktree", ""))
        if not path_text:
            continue
        worktree_path = Path(path_text)
        status = str(_run(runner, worktree_path, "status", "--porcelain=v1") or "")
        workspace = _workspace_counts(status)
        branch_ref = block.get("branch")
        branch = None
        if isinstance(branch_ref, str) and branch_ref.startswith("refs/heads/"):
            branch = branch_ref.removeprefix("refs/heads/")
        evidence.append(
            _evidence(
                evidence_id=f"ev_git_worktree_{index}",
                subject={"type": "worktree", "identifier": path_text},
                observation={
                    "path": path_text,
                    "head_sha": block.get("HEAD"),
                    "branch": branch,
                    "detached": bool(block.get("detached")),
                    "locked": block.get("locked") if "locked" in block else None,
                    "prunable": block.get("prunable") if "prunable" in block else None,
                    **workspace,
                },
                repository=repository,
                target_sha=target_sha,
            )
        )
    return evidence


def collect_stashes(repo: Path, target_ref: str) -> list[dict[str, Any]]:
    runner = ReadOnlyCommandRunner()
    repository = str(_run(runner, repo, "rev-parse", "--show-toplevel"))
    target_sha = str(_run(runner, repo, "rev-parse", target_ref))
    raw = str(
        _run(
            runner,
            repo,
            "stash",
            "list",
            "--format=%gd%x00%H%x00%ci%x00%gs",
        )
        or ""
    )
    evidence: list[dict[str, Any]] = []
    for index, line in enumerate(raw.splitlines()):
        parts = line.split("\x00")
        if len(parts) != 4:
            continue
        name, sha, created_at, message = parts
        evidence.append(
            _evidence(
                evidence_id=f"ev_git_stash_{index}",
                subject={"type": "stash", "identifier": name},
                observation={
                    "name": name,
                    "sha": sha,
                    "created_at": created_at,
                    "message": message,
                },
                repository=repository,
                target_sha=target_sha,
            )
        )
    return evidence
