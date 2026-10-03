from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from repo_assurance.collectors.filesystem import list_commit_paths, read_commit_text
from repo_assurance.core.schema import validate_document
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner
from repo_assurance.security.redaction import sanitize_evidence


class Runner(Protocol):
    def run(self, argv, *, cwd=None, stdin_text=None): ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _workflow_paths(repo: Path, target_commit_sha: str) -> list[str]:
    return [
        path
        for path in list_commit_paths(repo, target_commit_sha)
        if path.startswith(".github/workflows/")
        and path.rsplit(".", 1)[-1].lower() in {"yml", "yaml"}
    ]


def _tool_version(stdout: str) -> str | None:
    return next((line.strip() for line in stdout.splitlines() if line.strip()), None)


def _diagnostics(stdout: str) -> list[dict[str, Any]] | None:
    try:
        payload = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return None
    if isinstance(payload, Mapping):
        raw_items = [payload]
    elif isinstance(payload, list):
        raw_items = payload
    else:
        return None

    normalized: list[dict[str, Any]] = []
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        item: dict[str, Any] = {}
        for key in ("message", "filepath", "kind"):
            value = raw.get(key)
            if isinstance(value, str):
                item[key] = value
        for key in ("line", "column", "end_column"):
            value = raw.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                item[key] = value
        normalized.append(item)
    return normalized


def _evidence(
    *,
    repository: str,
    target_commit_sha: str,
    path: str,
    state: str,
    version: str | None,
    exit_code: int,
    diagnostics: list[dict[str, Any]],
    error_code: str | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]
    observation: dict[str, Any] = {
        "path": path,
        "actionlint_state": state,
        "tool_name": "actionlint",
        "tool_version": version,
        "exit_code": exit_code,
        "invocation": {
            "mode": "stdin",
            "format": "json",
            "external_integrations": {
                "shellcheck": False,
                "pyflakes": False,
            },
            "stdin_filename": path,
        },
        "diagnostics": diagnostics,
    }
    if error_code:
        observation["error_code"] = error_code

    item = {
        "schema_version": "evidence/v1",
        "id": f"ev_actionlint_{digest}",
        "kind": "execution",
        "source": {
            "provider": "actionlint",
            "mechanism": "stdin",
            "collector": "actionlint/v1",
        },
        "subject": {"type": "github_workflow", "identifier": path},
        "observation": observation,
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_commit_sha,
        },
        "collected_at": _now(),
        "visibility": {
            "completeness": "complete" if state in {"PASS", "FINDING"} else "unknown",
            "permission_limited": False,
            "retention_limited": False,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def collect_actionlint_evidence(
    repo: Path,
    *,
    repository: str,
    target_commit_sha: str,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    """Run actionlint against immutable workflow bytes without touching the checkout."""
    paths = _workflow_paths(repo, target_commit_sha)
    if not paths:
        return []

    transport = runner or ReadOnlyCommandRunner()
    version_result = transport.run(["actionlint", "-version"])
    version = _tool_version(version_result.stdout)

    if version_result.returncode == 127:
        return [
            _evidence(
                repository=repository,
                target_commit_sha=target_commit_sha,
                path=path,
                state="UNAVAILABLE",
                version=None,
                exit_code=127,
                diagnostics=[],
                error_code="ACTIONLINT_NOT_FOUND",
            )
            for path in paths
        ]
    if version_result.returncode != 0:
        return [
            _evidence(
                repository=repository,
                target_commit_sha=target_commit_sha,
                path=path,
                state="UNKNOWN_ERROR",
                version=version,
                exit_code=version_result.returncode,
                diagnostics=[],
                error_code=f"ACTIONLINT_VERSION_EXIT_{version_result.returncode}",
            )
            for path in paths
        ]

    evidence: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="repo-assurance-actionlint-") as temp:
        isolated_cwd = Path(temp)
        for path in paths:
            text = read_commit_text(repo, target_commit_sha, path)
            if text is None:
                evidence.append(
                    _evidence(
                        repository=repository,
                        target_commit_sha=target_commit_sha,
                        path=path,
                        state="UNKNOWN_ERROR",
                        version=version,
                        exit_code=1,
                        diagnostics=[],
                        error_code="SOURCE_SNAPSHOT_READ_FAILED",
                    )
                )
                continue

            argv = [
                "actionlint",
                "-no-color",
                "-shellcheck=",
                "-pyflakes=",
                "-format",
                "{{json .}}",
                "-stdin-filename",
                path,
                "-",
            ]
            result = transport.run(
                argv,
                cwd=isolated_cwd,
                stdin_text=text,
            )

            if result.returncode not in {0, 1}:
                evidence.append(
                    _evidence(
                        repository=repository,
                        target_commit_sha=target_commit_sha,
                        path=path,
                        state="UNKNOWN_ERROR",
                        version=version,
                        exit_code=result.returncode,
                        diagnostics=[],
                        error_code=f"ACTIONLINT_EXIT_{result.returncode}",
                    )
                )
                continue

            diagnostics = _diagnostics(result.stdout)
            if diagnostics is None:
                evidence.append(
                    _evidence(
                        repository=repository,
                        target_commit_sha=target_commit_sha,
                        path=path,
                        state="UNKNOWN_ERROR",
                        version=version,
                        exit_code=result.returncode,
                        diagnostics=[],
                        error_code="MALFORMED_ACTIONLINT_OUTPUT",
                    )
                )
                continue

            if diagnostics:
                state = "FINDING"
                error_code = None
            elif result.returncode == 0:
                state = "PASS"
                error_code = None
            else:
                state = "UNKNOWN_ERROR"
                error_code = "ACTIONLINT_FAILED_WITHOUT_DIAGNOSTICS"

            evidence.append(
                _evidence(
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    path=path,
                    state=state,
                    version=version,
                    exit_code=result.returncode,
                    diagnostics=diagnostics,
                    error_code=error_code,
                )
            )

    return evidence
