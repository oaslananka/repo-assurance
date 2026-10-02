from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from repo_assurance.collectors.github import GitHubAccessState, classify_gh_error
from repo_assurance.core.schema import validate_document
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner
from repo_assurance.security.redaction import sanitize_evidence


class Runner(Protocol):
    def run(self, argv, *, cwd=None): ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _error_code(result) -> str:
    combined = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"HTTP\s+(\d{3})", combined, re.IGNORECASE)
    return f"HTTP_{match.group(1)}" if match else "GH_COMMAND_FAILED"


def _visibility(access_state: GitHubAccessState, *, partial: bool = False, retention_limited: bool = False) -> dict[str, Any]:
    permission_limited = access_state in {GitHubAccessState.UNKNOWN_PERMISSION, GitHubAccessState.AUTH_FAILED}
    if access_state is not GitHubAccessState.AVAILABLE or partial or retention_limited:
        completeness = "partial" if access_state in {GitHubAccessState.AVAILABLE, GitHubAccessState.PARTIAL} else "unknown"
    else:
        completeness = "complete"
    return {
        "completeness": completeness,
        "permission_limited": permission_limited,
        "retention_limited": retention_limited,
    }


def _evidence(
    *,
    evidence_id: str,
    kind: str,
    repository: str,
    target_commit_sha: str,
    subject: dict[str, Any],
    observation: dict[str, Any],
    visibility: dict[str, Any],
) -> dict[str, Any]:
    item = {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {"provider": "github", "mechanism": "gh-api", "collector": "github-actions-history/v1"},
        "subject": subject,
        "observation": observation,
        "snapshot": {"repository": repository, "target_commit_sha": target_commit_sha},
        "collected_at": _iso(_now()),
        "visibility": visibility,
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def _normalize_run(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "head_sha": item.get("head_sha"),
        "run_attempt": item.get("run_attempt"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "event": item.get("event"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "run_started_at": item.get("run_started_at"),
    }


def collect_workflows(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    result = transport.run(["gh", "api", f"/repos/{repository}/actions/workflows?per_page=100"])
    state = classify_gh_error(result)
    subject = {"type": "repository", "identifier": repository}
    if state is not GitHubAccessState.AVAILABLE:
        return [_evidence(
            evidence_id="ev_github_workflows",
            kind="github_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            subject=subject,
            observation={"access_state": state.value, "error_code": _error_code(result)},
            visibility=_visibility(state),
        )]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [_evidence(
            evidence_id="ev_github_workflows",
            kind="github_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            subject=subject,
            observation={"access_state": "UNKNOWN_ERROR", "error_code": "MALFORMED_JSON"},
            visibility=_visibility(GitHubAccessState.UNKNOWN_ERROR),
        )]
    raw_workflows = payload.get("workflows", []) if isinstance(payload, dict) else []
    workflows = [
        {
            "id": item.get("id"),
            "name": item.get("name"),
            "path": item.get("path"),
            "state": item.get("state"),
        }
        for item in raw_workflows
        if isinstance(item, dict)
    ]
    return [_evidence(
        evidence_id="ev_github_workflows",
        kind="github_state",
        repository=repository,
        target_commit_sha=target_commit_sha,
        subject=subject,
        observation={"access_state": "AVAILABLE", "workflows": workflows},
        visibility=_visibility(GitHubAccessState.AVAILABLE),
    )]


def collect_workflow_history(
    *,
    repository: str,
    workflow_id: int | str,
    target_commit_sha: str,
    max_days: int,
    max_runs: int,
    runner: Runner | None = None,
    now: datetime | None = None,
    known_retention_days: int | None = None,
) -> list[dict[str, Any]]:
    if max_days <= 0 or max_runs <= 0:
        raise ValueError("history bounds must be positive")
    transport = runner or ReadOnlyCommandRunner()
    current = now or _now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    cutoff = current - timedelta(days=max_days)
    retention_limited = known_retention_days is not None and known_retention_days < max_days
    subject = {"type": "github_workflow", "identifier": str(workflow_id)}

    runs: list[dict[str, Any]] = []
    page = 1
    total_count: int | None = None
    raw_seen = 0
    cutoff_reached = False
    truncated_by_run_limit = False
    partial_error: tuple[str, str] | None = None

    while len(runs) < max_runs:
        endpoint = f"/repos/{repository}/actions/workflows/{workflow_id}/runs?per_page=100&page={page}"
        result = transport.run(["gh", "api", endpoint])
        state = classify_gh_error(result)
        if state is not GitHubAccessState.AVAILABLE:
            if not runs:
                return [_evidence(
                    evidence_id=f"ev_github_workflow_history_{workflow_id}",
                    kind="github_history",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    subject=subject,
                    observation={"access_state": state.value, "error_code": _error_code(result)},
                    visibility=_visibility(state),
                )]
            partial_error = (state.value, _error_code(result))
            break
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            if not runs:
                return [_evidence(
                    evidence_id=f"ev_github_workflow_history_{workflow_id}",
                    kind="github_history",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    subject=subject,
                    observation={"access_state": "UNKNOWN_ERROR", "error_code": "MALFORMED_JSON"},
                    visibility=_visibility(GitHubAccessState.UNKNOWN_ERROR),
                )]
            partial_error = ("UNKNOWN_ERROR", "MALFORMED_JSON")
            break
        if not isinstance(payload, dict):
            partial_error = ("UNKNOWN_ERROR", "UNEXPECTED_JSON_SHAPE")
            break
        if isinstance(payload.get("total_count"), int):
            total_count = int(payload["total_count"])
        page_runs = payload.get("workflow_runs")
        if not isinstance(page_runs, list):
            partial_error = ("UNKNOWN_ERROR", "UNEXPECTED_JSON_SHAPE")
            break
        if not page_runs:
            break

        stop_page = False
        for raw in page_runs:
            if not isinstance(raw, dict):
                continue
            raw_seen += 1
            created = _parse_time(raw.get("created_at"))
            if created is not None and created < cutoff:
                cutoff_reached = True
                stop_page = True
                break
            runs.append(_normalize_run(raw))
            if len(runs) >= max_runs:
                truncated_by_run_limit = True
                stop_page = True
                break
        if stop_page:
            break
        if total_count is not None and raw_seen >= total_count:
            break
        page += 1

    observed_times = [parsed for item in runs if (parsed := _parse_time(item.get("created_at"))) is not None]
    exhausted_available = total_count is not None and raw_seen >= total_count
    window_complete = not retention_limited and not truncated_by_run_limit and partial_error is None and (cutoff_reached or exhausted_available)
    partial = retention_limited or truncated_by_run_limit or partial_error is not None or not window_complete
    access_state = "PARTIAL" if partial_error is not None else "AVAILABLE"

    observation: dict[str, Any] = {
        "access_state": access_state,
        "workflow_id": workflow_id,
        "runs": runs,
        "requested_days": max_days,
        "max_runs": max_runs,
        "window_complete": window_complete,
        "truncated_by_run_limit": truncated_by_run_limit,
        "retention_limited": retention_limited,
        "observation_start": _iso(min(observed_times)) if observed_times else None,
        "observation_end": _iso(max(observed_times)) if observed_times else None,
    }
    if partial_error is not None:
        observation["error_state"] = partial_error[0]
        observation["error_code"] = partial_error[1]

    return [_evidence(
        evidence_id=f"ev_github_workflow_history_{workflow_id}",
        kind="github_history",
        repository=repository,
        target_commit_sha=target_commit_sha,
        subject=subject,
        observation=observation,
        visibility=_visibility(
            GitHubAccessState.PARTIAL if partial_error else GitHubAccessState.AVAILABLE,
            partial=partial,
            retention_limited=retention_limited,
        ),
    )]


def summarize_workflow_history(history_evidence: dict[str, Any]) -> dict[str, Any]:
    observation = history_evidence.get("observation")
    if not isinstance(observation, dict) or observation.get("access_state") not in {"AVAILABLE", "PARTIAL"}:
        return {
            "runs_analyzed": 0,
            "success": 0,
            "failure": 0,
            "cancelled": 0,
            "skipped": 0,
            "consecutive_failures": 0,
            "last_run": None,
            "last_success": None,
        }
    raw_runs = observation.get("runs")
    runs = [item for item in raw_runs if isinstance(item, dict)] if isinstance(raw_runs, list) else []
    runs = sorted(runs, key=lambda item: item.get("created_at") or "", reverse=True)

    counts = {"success": 0, "failure": 0, "cancelled": 0, "skipped": 0}
    for item in runs:
        conclusion = item.get("conclusion")
        if conclusion in counts:
            counts[str(conclusion)] += 1

    consecutive_failures = 0
    for item in runs:
        if item.get("conclusion") == "failure":
            consecutive_failures += 1
        else:
            break

    last_success = next((item.get("created_at") for item in runs if item.get("conclusion") == "success"), None)
    return {
        "runs_analyzed": len(runs),
        **counts,
        "consecutive_failures": consecutive_failures,
        "last_run": runs[0].get("created_at") if runs else None,
        "last_success": last_success,
    }
