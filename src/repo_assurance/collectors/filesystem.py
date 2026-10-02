from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from repo_assurance.core.schema import validate_document
from repo_assurance.security.redaction import sanitize_evidence
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence(
    *,
    evidence_id: str,
    kind: str,
    repository: str,
    target_commit_sha: str,
    subject: dict[str, Any],
    observation: dict[str, Any],
    collector: str,
) -> dict[str, Any]:
    item = {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {
            "provider": "filesystem",
            "mechanism": "read",
            "collector": collector,
        },
        "subject": subject,
        "observation": observation,
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_commit_sha,
        },
        "collected_at": _now(),
        "visibility": {
            "completeness": "complete",
            "permission_limited": False,
            "retention_limited": False,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized




class SourceSnapshotError(RuntimeError):
    """Raised when immutable source content cannot be read from Git objects."""


def list_commit_paths(
    repo: Path,
    target_commit_sha: str,
    *,
    runner: ReadOnlyCommandRunner | None = None,
) -> list[str]:
    transport = runner or ReadOnlyCommandRunner()
    result = transport.run(
        ["git", "ls-tree", "-r", "--name-only", "--full-tree", target_commit_sha],
        cwd=repo,
    )
    if result.returncode != 0:
        raise SourceSnapshotError(
            result.stderr.strip() or f"unable to list source tree for {target_commit_sha}"
        )
    return sorted(line for line in result.stdout.splitlines() if line)


def read_commit_text(
    repo: Path,
    target_commit_sha: str,
    relative_path: str,
    *,
    runner: ReadOnlyCommandRunner | None = None,
) -> str | None:
    transport = runner or ReadOnlyCommandRunner()
    result = transport.run(
        ["git", "show", f"{target_commit_sha}:{relative_path}"],
        cwd=repo,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def collect_repository_profile_evidence(
    *,
    repository: str,
    target_commit_sha: str,
    profile: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return [
        _evidence(
            evidence_id="ev_repository_profile",
            kind="source",
            repository=repository,
            target_commit_sha=target_commit_sha,
            subject={"type": "repository", "identifier": repository},
            observation=dict(profile),
            collector="repository-profile/v1",
        )
    ]


def collect_workflow_sources(
    repo: Path,
    *,
    repository: str,
    target_commit_sha: str,
) -> list[dict[str, Any]]:
    paths = [
        path
        for path in list_commit_paths(repo, target_commit_sha)
        if path.startswith(".github/workflows/")
        and path.rsplit(".", 1)[-1].lower() in {"yml", "yaml"}
    ]

    evidence: list[dict[str, Any]] = []
    for relative in paths:
        text = read_commit_text(repo, target_commit_sha, relative)
        if text is None:
            continue
        digest = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:12]
        evidence.append(
            _evidence(
                evidence_id=f"ev_workflow_source_{digest}",
                kind="source",
                repository=repository,
                target_commit_sha=target_commit_sha,
                subject={"type": "github_workflow", "identifier": relative},
                observation={
                    "path": relative,
                    "text": text,
                    "actionlint_state": "UNAVAILABLE",
                },
                collector="workflow-source/v1",
            )
        )
    return evidence

