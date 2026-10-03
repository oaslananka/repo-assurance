from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import StrEnum
from urllib.parse import parse_qs, urlparse
from typing import Any, Protocol

from repo_assurance.core.schema import validate_document
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner
from repo_assurance.security.redaction import sanitize_evidence


class GitHubAccessState(StrEnum):
    AVAILABLE = "AVAILABLE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN_PERMISSION = "UNKNOWN_PERMISSION"
    AUTH_FAILED = "AUTH_FAILED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class Runner(Protocol):
    def run(self, argv, *, cwd=None): ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _http_code(text: str) -> str | None:
    match = re.search(r"HTTP\s+(\d{3})", text, re.IGNORECASE)
    return match.group(1) if match else None


def classify_gh_error(result) -> GitHubAccessState:
    if result.returncode == 0:
        return GitHubAccessState.AVAILABLE
    if result.returncode == 127:
        return GitHubAccessState.UNAVAILABLE
    combined = f"{result.stdout}\n{result.stderr}"
    code = _http_code(combined)
    if code == "401" or "bad credentials" in combined.lower() or "authentication failed" in combined.lower():
        return GitHubAccessState.AUTH_FAILED
    if code in {"403", "404"} or "resource not accessible" in combined.lower():
        return GitHubAccessState.UNKNOWN_PERMISSION
    return GitHubAccessState.UNKNOWN_ERROR


def _normalized_error_code(result) -> str:
    code = _http_code(f"{result.stdout}\n{result.stderr}")
    return f"HTTP_{code}" if code else "GH_COMMAND_FAILED"


def _make_evidence(
    *,
    evidence_id: str,
    repository: str,
    target_commit_sha: str,
    observation: dict[str, Any],
    access_state: GitHubAccessState,
) -> dict[str, Any]:
    permission_limited = access_state in {
        GitHubAccessState.UNKNOWN_PERMISSION,
        GitHubAccessState.AUTH_FAILED,
    }
    item = {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "github_state",
        "source": {"provider": "github", "mechanism": "gh-api", "collector": "github/v1"},
        "subject": {"type": "repository", "identifier": repository},
        "observation": observation,
        "snapshot": {"repository": repository, "target_commit_sha": target_commit_sha},
        "collected_at": _now(),
        "visibility": {
            "completeness": "complete" if access_state is GitHubAccessState.AVAILABLE else "unknown",
            "permission_limited": permission_limited,
            "retention_limited": False,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def _collect_json(
    *,
    argv: list[str],
    evidence_id: str,
    repository: str,
    target_commit_sha: str,
    runner: Runner,
) -> tuple[dict[str, Any] | list[Any] | None, dict[str, Any] | None]:
    result = runner.run(argv)
    state = classify_gh_error(result)
    if state is not GitHubAccessState.AVAILABLE:
        evidence = _make_evidence(
            evidence_id=evidence_id,
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={"access_state": state.value, "error_code": _normalized_error_code(result)},
            access_state=state,
        )
        return None, evidence
    if result.stdout is None:
        evidence = _make_evidence(
            evidence_id=evidence_id,
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={
                "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                "error_code": "MISSING_STDOUT",
            },
            access_state=GitHubAccessState.UNKNOWN_ERROR,
        )
        return None, evidence
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        evidence = _make_evidence(
            evidence_id=evidence_id,
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={
                "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                "error_code": "MALFORMED_JSON",
            },
            access_state=GitHubAccessState.UNKNOWN_ERROR,
        )
        return None, evidence
    return payload, None


def collect_repository_state(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    payload, error = _collect_json(
        argv=["gh", "api", f"/repos/{repository}"],
        evidence_id="ev_github_repository",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
    )
    if error is not None:
        return [error]
    if not isinstance(payload, dict):
        return [
            _make_evidence(
                evidence_id="ev_github_repository",
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={"access_state": "UNKNOWN_ERROR", "error_code": "UNEXPECTED_JSON_SHAPE"},
                access_state=GitHubAccessState.UNKNOWN_ERROR,
            )
        ]
    security_and_analysis: dict[str, Any] = {}
    raw_security = payload.get("security_and_analysis")
    if isinstance(raw_security, dict):
        for key, value in sorted(raw_security.items()):
            if isinstance(value, dict) and value.get("status") is not None:
                security_and_analysis[str(key)] = str(value["status"])

    observation = {
        "access_state": GitHubAccessState.AVAILABLE.value,
        "full_name": payload.get("full_name"),
        "default_branch": payload.get("default_branch"),
        "private": payload.get("private"),
        "archived": payload.get("archived"),
        "fork": payload.get("fork"),
        "delete_branch_on_merge": payload.get("delete_branch_on_merge"),
        "allow_merge_commit": payload.get("allow_merge_commit"),
        "allow_rebase_merge": payload.get("allow_rebase_merge"),
        "allow_squash_merge": payload.get("allow_squash_merge"),
        "security_and_analysis": security_and_analysis,
    }
    return [
        _make_evidence(
            evidence_id="ev_github_repository",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation=observation,
            access_state=GitHubAccessState.AVAILABLE,
        )
    ]


def collect_rulesets(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    payload, error = _collect_json(
        argv=["gh", "api", f"/repos/{repository}/rulesets?includes_parents=true"],
        evidence_id="ev_github_rulesets",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
    )
    if error is not None:
        return [error]
    if not isinstance(payload, list):
        return [
            _make_evidence(
                evidence_id="ev_github_rulesets",
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={"access_state": "UNKNOWN_ERROR", "error_code": "UNEXPECTED_JSON_SHAPE"},
                access_state=GitHubAccessState.UNKNOWN_ERROR,
            )
        ]
    rulesets = [
        {
            "id": item.get("id"),
            "name": item.get("name"),
            "enforcement": item.get("enforcement"),
            "target": item.get("target"),
            "source_type": item.get("source_type"),
            "source": item.get("source"),
            "conditions": item.get("conditions"),
            "bypass_actors": item.get("bypass_actors") or [],
            "rules": item.get("rules") or [],
        }
        for item in payload
        if isinstance(item, dict)
    ]
    return [
        _make_evidence(
            evidence_id="ev_github_rulesets",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={"access_state": GitHubAccessState.AVAILABLE.value, "rulesets": rulesets},
            access_state=GitHubAccessState.AVAILABLE,
        )
    ]


def collect_default_branch_state(
    repository: str,
    branch: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    payload, error = _collect_json(
        argv=["gh", "api", f"/repos/{repository}/branches/{branch}"],
        evidence_id="ev_github_default_branch",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
    )
    if error is not None:
        return [error]
    if not isinstance(payload, dict):
        return [_make_evidence(
            evidence_id="ev_github_default_branch",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={"access_state": "UNKNOWN_ERROR", "error_code": "UNEXPECTED_JSON_SHAPE"},
            access_state=GitHubAccessState.UNKNOWN_ERROR,
        )]

    protection = payload.get("protection")
    required_checks: set[str] = set()
    required_details: dict[str, dict[str, Any]] = {}
    if isinstance(protection, dict):
        status_checks = protection.get("required_status_checks")
        if isinstance(status_checks, dict):
            contexts = status_checks.get("contexts")
            if isinstance(contexts, list):
                for item in contexts:
                    if not item:
                        continue
                    context = str(item)
                    required_checks.add(context)
                    required_details.setdefault(
                        context,
                        {"context": context, "app_id": None},
                    )
            checks = status_checks.get("checks")
            if isinstance(checks, list):
                for item in checks:
                    if not isinstance(item, dict) or not item.get("context"):
                        continue
                    context = str(item["context"])
                    required_checks.add(context)
                    app_id = item.get("app_id")
                    required_details[context] = {
                        "context": context,
                        "app_id": app_id if isinstance(app_id, int) and not isinstance(app_id, bool) else None,
                    }

    return [_make_evidence(
        evidence_id="ev_github_default_branch",
        repository=repository,
        target_commit_sha=target_commit_sha,
        observation={
            "access_state": GitHubAccessState.AVAILABLE.value,
            "name": payload.get("name") or branch,
            "protected": bool(payload.get("protected")),
            "required_status_checks": sorted(required_checks),
            "required_status_check_details": [
                required_details[context]
                for context in sorted(required_details)
            ],
        },
        access_state=GitHubAccessState.AVAILABLE,
    )]


def collect_commit_checks(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    payload, error = _collect_json(
        argv=["gh", "api", f"/repos/{repository}/commits/{target_commit_sha}/check-runs?per_page=100"],
        evidence_id="ev_github_checks",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
    )
    if error is not None:
        return [error]
    if not isinstance(payload, dict) or not isinstance(payload.get("check_runs"), list):
        return [_make_evidence(
            evidence_id="ev_github_checks",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={"access_state": "UNKNOWN_ERROR", "error_code": "UNEXPECTED_JSON_SHAPE"},
            access_state=GitHubAccessState.UNKNOWN_ERROR,
        )]

    names = sorted({
        str(item.get("name"))
        for item in payload["check_runs"]
        if isinstance(item, dict) and item.get("name")
    })
    check_runs: list[dict[str, Any]] = []
    for raw in payload["check_runs"]:
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        app = raw.get("app")
        app_id = app.get("id") if isinstance(app, dict) else None
        app_slug = app.get("slug") if isinstance(app, dict) else None
        app_name = app.get("name") if isinstance(app, dict) else None
        check_suite = raw.get("check_suite")
        check_suite_id = check_suite.get("id") if isinstance(check_suite, dict) else None

        workflow_run_id: int | None = None
        job_id: int | None = None
        if app_slug == "github-actions":
            details_url = raw.get("details_url")
            if isinstance(details_url, str):
                match = re.search(r"/actions/runs/(\d+)(?:/job/(\d+))?", details_url)
                if match:
                    workflow_run_id = int(match.group(1))
                    if match.group(2):
                        job_id = int(match.group(2))

        details_host: str | None = None
        details_path = ""
        details_query: dict[str, str] = {}
        details_url = raw.get("details_url")
        if (
            app_slug in {"sonarqubecloud", "socket-security"}
            and isinstance(details_url, str)
            and details_url
        ):
            parsed = urlparse(details_url)
            details_host = parsed.hostname
            details_path = parsed.path
            if app_slug == "sonarqubecloud":
                query = parse_qs(parsed.query, keep_blank_values=False)
                details_query = {
                    key: values[0]
                    for key, values in query.items()
                    if key in {"id", "branch"} and values
                }

        check_runs.append({
            "id": raw.get("id"),
            "name": str(raw["name"]),
            "status": raw.get("status"),
            "conclusion": raw.get("conclusion"),
            "app_id": app_id if isinstance(app_id, int) and not isinstance(app_id, bool) else None,
            "app_slug": str(app_slug) if app_slug else None,
            "app_name": str(app_name) if app_name else None,
            "started_at": raw.get("started_at"),
            "completed_at": raw.get("completed_at"),
            "details_host": details_host,
            "details_path": details_path,
            "details_query": details_query,
            "check_suite_id": check_suite_id if isinstance(check_suite_id, int) else None,
            "workflow_run_id": workflow_run_id,
            "job_id": job_id,
        })

    return [_make_evidence(
        evidence_id="ev_github_checks",
        repository=repository,
        target_commit_sha=target_commit_sha,
        observation={
            "access_state": GitHubAccessState.AVAILABLE.value,
            "check_names": names,
            "check_runs": check_runs,
        },
        access_state=GitHubAccessState.AVAILABLE,
    )]
