from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from repo_assurance.collectors.github import (
    GitHubAccessState,
    classify_gh_error,
)
from repo_assurance.core.schema import validate_document
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner
from repo_assurance.security.redaction import sanitize_evidence


class Runner(Protocol):
    def run(self, argv, *, cwd=None): ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _http_error_code(result) -> str:
    text = f"{result.stdout}\n{result.stderr}"
    import re

    match = re.search(r"HTTP\s+(\d{3})", text, re.IGNORECASE)
    return f"HTTP_{match.group(1)}" if match else "GH_COMMAND_FAILED"


def _evidence(
    *,
    evidence_id: str,
    kind: str,
    repository: str,
    target_commit_sha: str,
    observation: dict[str, Any],
    access_state: GitHubAccessState,
) -> dict[str, Any]:
    item = {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": kind,
        "source": {
            "provider": "github",
            "mechanism": "gh-api",
            "collector": "github-security/v1",
        },
        "subject": {"type": "repository", "identifier": repository},
        "observation": observation,
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_commit_sha,
        },
        "collected_at": _now(),
        "visibility": {
            "completeness": (
                "complete"
                if access_state is GitHubAccessState.AVAILABLE
                else "unknown"
            ),
            "permission_limited": access_state in {
                GitHubAccessState.UNKNOWN_PERMISSION,
                GitHubAccessState.AUTH_FAILED,
            },
            "retention_limited": False,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def _flatten_slurp(payload: object) -> list[Mapping[str, Any]] | None:
    if not isinstance(payload, list):
        return None

    flattened: list[Mapping[str, Any]] = []
    for page in payload:
        if isinstance(page, list):
            flattened.extend(
                item for item in page if isinstance(item, Mapping)
            )
        elif isinstance(page, Mapping):
            flattened.append(page)
        else:
            return None
    return flattened


def _collect_list(
    *,
    argv: list[str],
    evidence_id: str,
    kind: str,
    repository: str,
    target_commit_sha: str,
    runner: Runner,
    key: str,
    normalizer,
) -> list[dict[str, Any]]:
    result = runner.run(argv)
    state = classify_gh_error(result)
    if state is not GitHubAccessState.AVAILABLE:
        return [
            _evidence(
                evidence_id=evidence_id,
                kind=kind,
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": state.value,
                    "error_code": _http_error_code(result),
                },
                access_state=state,
            )
        ]

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [
            _evidence(
                evidence_id=evidence_id,
                kind=kind,
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                    "error_code": "MALFORMED_JSON",
                },
                access_state=GitHubAccessState.UNKNOWN_ERROR,
            )
        ]

    items = _flatten_slurp(payload)
    if items is None:
        return [
            _evidence(
                evidence_id=evidence_id,
                kind=kind,
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                    "error_code": "UNEXPECTED_JSON_SHAPE",
                },
                access_state=GitHubAccessState.UNKNOWN_ERROR,
            )
        ]

    normalized = [normalizer(item) for item in items]
    return [
        _evidence(
            evidence_id=evidence_id,
            kind=kind,
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={
                "access_state": GitHubAccessState.AVAILABLE.value,
                key: normalized,
            },
            access_state=GitHubAccessState.AVAILABLE,
        )
    ]


def _code_scanning_analysis(item: Mapping[str, Any]) -> dict[str, Any]:
    tool = item.get("tool")
    normalized_tool = (
        {
            "name": tool.get("name"),
            "version": tool.get("version"),
        }
        if isinstance(tool, Mapping)
        else {}
    )
    return {
        "id": item.get("id"),
        "ref": item.get("ref"),
        "commit_sha": item.get("commit_sha"),
        "analysis_key": item.get("analysis_key"),
        "category": item.get("category"),
        "error": item.get("error"),
        "created_at": item.get("created_at"),
        "results_count": item.get("results_count"),
        "rules_count": item.get("rules_count"),
        "tool": normalized_tool,
    }


def collect_code_scanning_analyses(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    return _collect_list(
        argv=[
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"/repos/{repository}/code-scanning/analyses?per_page=100",
        ],
        evidence_id="ev_github_code_scanning_analyses",
        kind="github_state",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
        key="analyses",
        normalizer=_code_scanning_analysis,
    )


def _code_scanning_alert(item: Mapping[str, Any]) -> dict[str, Any]:
    tool = item.get("tool")
    rule = item.get("rule")
    instance = item.get("most_recent_instance")
    return {
        "number": item.get("number"),
        "state": item.get("state"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "dismissed_at": item.get("dismissed_at"),
        "dismissed_reason": item.get("dismissed_reason"),
        "tool": (
            {"name": tool.get("name")}
            if isinstance(tool, Mapping)
            else {}
        ),
        "rule": (
            {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "security_severity_level": rule.get(
                    "security_severity_level"
                ),
            }
            if isinstance(rule, Mapping)
            else {}
        ),
        "most_recent_instance": (
            {
                "commit_sha": instance.get("commit_sha"),
                "ref": instance.get("ref"),
                "state": instance.get("state"),
            }
            if isinstance(instance, Mapping)
            else {}
        ),
    }


def collect_code_scanning_alerts(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    return _collect_list(
        argv=[
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"/repos/{repository}/code-scanning/alerts?state=open&per_page=100",
        ],
        evidence_id="ev_github_code_scanning_alerts",
        kind="github_state",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
        key="alerts",
        normalizer=_code_scanning_alert,
    )


def _dependabot_alert(item: Mapping[str, Any]) -> dict[str, Any]:
    dependency = item.get("dependency")
    advisory = item.get("security_advisory")

    package_name: str | None = None
    ecosystem: str | None = None
    manifest_path: str | None = None
    scope: str | None = None
    if isinstance(dependency, Mapping):
        package = dependency.get("package")
        if isinstance(package, Mapping):
            package_name = (
                str(package.get("name"))
                if package.get("name") is not None
                else None
            )
            ecosystem = (
                str(package.get("ecosystem"))
                if package.get("ecosystem") is not None
                else None
            )
        elif package is not None:
            package_name = str(package)
        manifest_path = (
            str(dependency.get("manifest_path"))
            if dependency.get("manifest_path") is not None
            else None
        )
        scope = (
            str(dependency.get("scope"))
            if dependency.get("scope") is not None
            else None
        )

    normalized_advisory = {}
    if isinstance(advisory, Mapping):
        normalized_advisory = {
            "ghsa_id": advisory.get("ghsa_id"),
            "cve_id": advisory.get("cve_id"),
            "severity": advisory.get("severity"),
            "summary": advisory.get("summary"),
        }

    return {
        "number": item.get("number"),
        "state": item.get("state"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "dismissed_at": item.get("dismissed_at"),
        "dismissed_reason": item.get("dismissed_reason"),
        "dependency": {
            "package": package_name,
            "ecosystem": ecosystem,
            "manifest_path": manifest_path,
            "scope": scope,
        },
        "security_advisory": normalized_advisory,
    }


def collect_dependabot_alerts(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    return _collect_list(
        argv=[
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"/repos/{repository}/dependabot/alerts?state=open&per_page=100",
        ],
        evidence_id="ev_github_dependabot_alerts",
        kind="dependency_state",
        repository=repository,
        target_commit_sha=target_commit_sha,
        runner=transport,
        key="alerts",
        normalizer=_dependabot_alert,
    )


def _secret_alert(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "number": item.get("number"),
        "state": item.get("state"),
        "secret_type": item.get("secret_type"),
        "secret_type_display_name": item.get(
            "secret_type_display_name"
        ),
        "resolution": item.get("resolution"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def collect_secret_scanning_alerts(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    jq = (
        '.[] | {number,state,secret_type,secret_type_display_name,'
        'resolution,created_at,updated_at}'
    )
    result = transport.run([
        "gh",
        "api",
        "--paginate",
        f"/repos/{repository}/secret-scanning/alerts?state=open&per_page=100",
        "--jq",
        jq,
    ])
    state = classify_gh_error(result)
    if state is not GitHubAccessState.AVAILABLE:
        return [
            _evidence(
                evidence_id="ev_github_secret_scanning_alerts",
                kind="github_state",
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": state.value,
                    "error_code": _http_error_code(result),
                },
                access_state=state,
            )
        ]

    alerts: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return [
                _evidence(
                    evidence_id="ev_github_secret_scanning_alerts",
                    kind="github_state",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    observation={
                        "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                        "error_code": "MALFORMED_JSON",
                    },
                    access_state=GitHubAccessState.UNKNOWN_ERROR,
                )
            ]
        if not isinstance(item, Mapping):
            return [
                _evidence(
                    evidence_id="ev_github_secret_scanning_alerts",
                    kind="github_state",
                    repository=repository,
                    target_commit_sha=target_commit_sha,
                    observation={
                        "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                        "error_code": "UNEXPECTED_JSON_SHAPE",
                    },
                    access_state=GitHubAccessState.UNKNOWN_ERROR,
                )
            ]
        alerts.append(_secret_alert(item))

    return [
        _evidence(
            evidence_id="ev_github_secret_scanning_alerts",
            kind="github_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation={
                "access_state": GitHubAccessState.AVAILABLE.value,
                "alerts": alerts,
            },
            access_state=GitHubAccessState.AVAILABLE,
        )
    ]


def collect_dependency_sbom(
    repository: str,
    target_commit_sha: str,
    *,
    runner: Runner | None = None,
) -> list[dict[str, Any]]:
    transport = runner or ReadOnlyCommandRunner()
    result = transport.run(
        ["gh", "api", f"/repos/{repository}/dependency-graph/sbom"]
    )
    state = classify_gh_error(result)
    if state is not GitHubAccessState.AVAILABLE:
        return [
            _evidence(
                evidence_id="ev_github_dependency_sbom",
                kind="dependency_state",
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": state.value,
                    "error_code": _http_error_code(result),
                },
                access_state=state,
            )
        ]

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = None
    sbom = payload.get("sbom") if isinstance(payload, Mapping) else None
    if not isinstance(sbom, Mapping):
        return [
            _evidence(
                evidence_id="ev_github_dependency_sbom",
                kind="dependency_state",
                repository=repository,
                target_commit_sha=target_commit_sha,
                observation={
                    "access_state": GitHubAccessState.UNKNOWN_ERROR.value,
                    "error_code": "UNEXPECTED_JSON_SHAPE",
                },
                access_state=GitHubAccessState.UNKNOWN_ERROR,
            )
        ]

    packages = sbom.get("packages")
    relationships = sbom.get("relationships")
    observation = {
        "access_state": GitHubAccessState.AVAILABLE.value,
        "sbom": {
            "name": sbom.get("name"),
            "spdx_version": sbom.get("spdxVersion"),
            "packages_count": len(packages) if isinstance(packages, list) else 0,
            "relationships_count": (
                len(relationships)
                if isinstance(relationships, list)
                else 0
            ),
        },
    }
    return [
        _evidence(
            evidence_id="ev_github_dependency_sbom",
            kind="dependency_state",
            repository=repository,
            target_commit_sha=target_commit_sha,
            observation=observation,
            access_state=GitHubAccessState.AVAILABLE,
        )
    ]

