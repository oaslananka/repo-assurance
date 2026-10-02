from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from repo_assurance.core.schema import validate_document
from repo_assurance.security.redaction import sanitize_evidence


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
    workflow_dir = repo / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []

    evidence: list[dict[str, Any]] = []
    paths = sorted(
        [*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")],
        key=lambda item: item.as_posix(),
    )
    for path in paths:
        relative = path.relative_to(repo).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
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
