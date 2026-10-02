from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from repo_assurance.collectors.github import GitHubAccessState, classify_gh_error
from repo_assurance.core.schema import validate_document
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner
from repo_assurance.security.redaction import sanitize_evidence


class Runner(Protocol):
    def run(self, argv, *, cwd=None): ...


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _http_error_code(result) -> str:
    combined = f"{result.stdout}\n{result.stderr}"
    import re
    match = re.search(r"HTTP\s+(\d{3})", combined, re.IGNORECASE)
    return f"HTTP_{match.group(1)}" if match else "GH_COMMAND_FAILED"


def _evidence(
    *,
    evidence_id: str,
    kind: str,
    repository: str,
    target_commit_sha: str,
    subject: dict[str, Any],
    observation: dict[str, Any],
    completeness: str = "complete",
    permission_limited: bool = False,
    retention_limited: bool = False,
) -> dict[str, Any]:
    item = {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {
            "provider": "github",
            "mechanism": "gh-api",
            "collector": "github-actions-history/v1",
        },
        "subject": subject,
        "observation": observation,
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_commit_sha,
        },
        "collected_at": _iso(_now()),
        "freshness": {
            "time_sensitive": True,
            "valid_as_of": _iso(_now()).split("T", 1)[0],
        },
        "visibility": {
            "completeness": completeness,
            "permission_limited": permission_limited,
            "retention_limited": retention_limited,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def _load_json(result) -> Any:
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def collect_workflows(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    result = transport.run([
        "gh", "api",
        f"/repos/{repository}/actions/workflows?per_page=100",
    ])
    state = classify_gh_error(result)
    subject = {"type": "repository", "identifier": repository}

    if state is not GitHubAccessState.AVAILABLE:
        return [_evidence(
            evidence_id="ev_github_workflows",
            kind="github_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            subject=subject,
            observation={
                "access_state": state.value,
                "error_code": _http_error_code(result),
                "workflows": [],
            },
            completeness="unknown",
            permission_limited=state in {
                GitHubAccessState.UNKNOWN_PERMISSION,
                GitHubAccessState.AUTH_FAILED,
            },
        )]

    payload = _load_json(result)
    if not isinstance(payload, dict) or not isinstance(payload.get("workflows"), list):
        return [_evidence(
            evidence_id="ev_github_workflows",
            kind="github_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            subject=subject,
            observation={
                "access_state": "UNKNOWN_ERROR",
                "error_code": "UNEXPECTED_JSON_SHAPE",
                "workflows": [],
            },
            completeness="unknown",
        )]

    workflows = []
    for item in payload["workflows"]:
        if not isinstance(item, dict):
            continue
        workflows.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "path": item.get("path"),
            "state": item.get("state"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
        })

    return [_evidence(
        evidence_id="ev_github_workflows",
        kind="github_state",
        repository=repository,
        target_commit_sha=target_commit_sha,
        subject=subject,
        observation={
            "access_state": "AVAILABLE",
            "workflows": workflows,
        },
    )]


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


def collect_workflow_history(
    *,
    repository: str,
    workflow_id: str,
    target_commit_sha: str,
    max_days: int,
    max_runs: int,
    runner: Runner | None = None,
    now: datetime | None = None,
    known_retention_days: int | None = None,
) -> list[dict[str, Any]]:
    if max_days <= 0:
        raise ValueError("max_days must be positive")
    if max_runs <= 0:
        raise ValueError("max_runs must be positive")

    transport = runner or ReadOnlyCommandRunner()
    current = (now or _now()).astimezone(timezone.utc)
    cutoff = current - timedelta(days=max_days)
    runs: list[dict[str, Any]] = []
    page = 1
    truncated_by_run_limit = False
    stopped_by_cutoff = False
    partial_error: dict[str, Any] | None = None

    while len(runs) < max_runs:
        result = transport.run([
            "gh", "api",
            f"/repos/{repository}/actions/workflows/{workflow_id}/runs?per_page=100&page={page}",
        ])
        state = classify_gh_error(result)
        if state is not GitHubAccessState.AVAILABLE:
            if page == 1:
                return [_evidence(
                    evidence_id=f"ev_github_workflow_history_{workflow_id}",
                    kind="github_history",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    subject={"type": "github_workflow", "identifier": str(workflow_id)},
                    observation={
                        "access_state": state.value,
                        "error_code": _http_error_code(result),
                        "runs": [],
                        "requested_max_days": max_days,
                        "requested_max_runs": max_runs,
                    },
                    completeness="unknown",
                    permission_limited=state in {
                        GitHubAccessState.UNKNOWN_PERMISSION,
                        GitHubAccessState.AUTH_FAILED,
                    },
                    retention_limited=bool(
                        known_retention_days is not None
                        and known_retention_days < max_days
                    ),
                )]
            partial_error = {
                "access_state": state.value,
                "error_code": _http_error_code(result),
                "failed_page": page,
            }
            break

        payload = _load_json(result)
        if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
            if page == 1:
                return [_evidence(
                    evidence_id=f"ev_github_workflow_history_{workflow_id}",
                    kind="github_history",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    subject={"type": "github_workflow", "identifier": str(workflow_id)},
                    observation={
                        "access_state": "UNKNOWN_ERROR",
                        "error_code": "UNEXPECTED_JSON_SHAPE",
                        "runs": [],
                        "requested_max_days": max_days,
                        "requested_max_runs": max_runs,
                    },
                    completeness="unknown",
                    retention_limited=bool(
                        known_retention_days is not None
                        and known_retention_days < max_days
                    ),
                )]
            partial_error = {
                "access_state": "UNKNOWN_ERROR",
                "error_code": "UNEXPECTED_JSON_SHAPE",
                "failed_page": page,
            }
            break

        page_runs = payload["workflow_runs"]
        if not page_runs:
            break

        for item in page_runs:
            if not isinstance(item, dict):
                continue
            created = _parse_time(item.get("created_at"))
            if created is not None and created < cutoff:
                stopped_by_cutoff = True
                break
            if len(runs) >= max_runs:
                truncated_by_run_limit = True
                break
            runs.append(_normalize_run(item))

        if stopped_by_cutoff or len(runs) >= max_runs:
            if len(runs) >= max_runs and len(page_runs) > 0:
                truncated_by_run_limit = True
            break

        page += 1

    retention_limited = bool(
        known_retention_days is not None and known_retention_days < max_days
    )
    incomplete = bool(partial_error or truncated_by_run_limit or retention_limited)
    observation: dict[str, Any] = {
        "access_state": "AVAILABLE" if partial_error is None else "PARTIAL",
        "workflow_id": str(workflow_id),
        "runs": runs,
        "requested_max_days": max_days,
        "requested_max_runs": max_runs,
        "cutoff": _iso(cutoff),
        "truncated_by_run_limit": truncated_by_run_limit,
        "stopped_by_cutoff": stopped_by_cutoff,
    }
    if partial_error:
        observation["partial_error"] = partial_error

    return [_evidence(
        evidence_id=f"ev_github_workflow_history_{workflow_id}",
        kind="github_history",
        repository=repository,
        target_commit_sha=target_commit_sha,
        subject={"type": "github_workflow", "identifier": str(workflow_id)},
        observation=observation,
        completeness="partial" if incomplete else "complete",
        permission_limited=bool(
            partial_error
            and partial_error.get("access_state") in {
                "UNKNOWN_PERMISSION", "AUTH_FAILED"
            }
        ),
        retention_limited=retention_limited,
    )]


def summarize_workflow_history(history_evidence: dict[str, Any]) -> dict[str, Any]:
    observation = history_evidence.get("observation", {})
    runs = observation.get("runs", []) if isinstance(observation, dict) else []
    if not isinstance(runs, list):
        runs = []

    counts = {
        "success": 0,
        "failure": 0,
        "cancelled": 0,
        "skipped": 0,
    }
    last_run: str | None = None
    last_success: str | None = None
    consecutive_failures = 0
    failure_prefix_active = True

    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        conclusion = run.get("conclusion")
        created_at = run.get("created_at")
        if index == 0 and created_at:
            last_run = str(created_at)
        if conclusion in counts:
            counts[str(conclusion)] += 1
        if last_success is None and conclusion == "success" and created_at:
            last_success = str(created_at)
        if failure_prefix_active:
            if conclusion == "failure":
                consecutive_failures += 1
            else:
                failure_prefix_active = False

    observed_dates = [
        _parse_time(run.get("created_at"))
        for run in runs
        if isinstance(run, dict)
    ]
    observed_dates = [item for item in observed_dates if item is not None]

    return {
        "runs_analyzed": len(runs),
        **counts,
        "consecutive_failures": consecutive_failures,
        "last_run": last_run,
        "last_success": last_success,
        "observation_start": _iso(min(observed_dates)) if observed_dates else None,
        "observation_end": _iso(max(observed_dates)) if observed_dates else None,
        "retention_limited": bool(
            history_evidence.get("visibility", {}).get("retention_limited")
        ),
    }
