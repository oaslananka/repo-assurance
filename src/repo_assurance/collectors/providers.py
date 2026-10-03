from __future__ import annotations

import hashlib
from typing import Any, Mapping

from repo_assurance.core.schema import validate_document
from repo_assurance.providers.registry import resolve_provider_adapter
from repo_assurance.security.redaction import sanitize_evidence


_IGNORED_APP_SLUGS = {"github-actions"}


def _latest_check(checks: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    return max(
        checks,
        key=lambda item: (
            str(item.get("completed_at") or ""),
            int(item.get("id") or 0),
        ),
    )


def _snapshot_context(
    github_checks: Mapping[str, Any],
) -> tuple[str, str]:
    snapshot = github_checks.get("snapshot")
    repository = (
        str(snapshot.get("repository"))
        if isinstance(snapshot, Mapping) and snapshot.get("repository")
        else "unknown"
    )
    target_sha = (
        str(snapshot.get("target_commit_sha"))
        if isinstance(snapshot, Mapping) and snapshot.get("target_commit_sha")
        else "0" * 40
    )
    return repository, target_sha


def collect_provider_states(
    github_checks: Mapping[str, Any],
    *,
    required_checks: list[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    observation = github_checks.get("observation")
    if not isinstance(observation, Mapping):
        return []
    if observation.get("access_state") != "AVAILABLE":
        return []

    raw_runs = observation.get("check_runs")
    if not isinstance(raw_runs, list):
        return []

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    adapters = {}
    for raw in raw_runs:
        if not isinstance(raw, Mapping):
            continue
        app_slug = str(raw.get("app_slug") or "").lower()
        if not app_slug or app_slug in _IGNORED_APP_SLUGS:
            continue
        adapter = resolve_provider_adapter(raw)
        grouped.setdefault(adapter.provider_id, []).append(raw)
        adapters[adapter.provider_id] = adapter

    repository, target_sha = _snapshot_context(github_checks)

    output: list[dict[str, Any]] = []
    for provider_id in sorted(grouped):
        checks = grouped[provider_id]
        adapter = adapters[provider_id]
        latest = _latest_check(checks)
        scope = adapter.scope(latest)
        latest_check_name = str(latest.get("name") or provider_id)

        if required_checks is None:
            enforcement_state = "UNKNOWN"
            contexts: list[str] = []
        else:
            matching: set[str] = set()
            for check in checks:
                current_check_name = str(check.get("name") or "")
                check_app_id = check.get("app_id")
                for requirement in required_checks:
                    context = str(requirement.get("context") or "")
                    required_app_id = requirement.get("app_id")
                    if current_check_name != context:
                        continue
                    if (
                        required_app_id is not None
                        and check_app_id != required_app_id
                    ):
                        continue
                    matching.add(context)
            contexts = sorted(matching)
            enforcement_state = "REQUIRED" if contexts else "NOT_REQUIRED"

        state = {
            "schema_version": "provider-state/v1",
            "provider": {
                "id": adapter.provider_id,
                "display_name": adapter.display_name,
                "adapter_id": adapter.adapter_id,
                "known_adapter": adapter.adapter_id != "generic-github-check/v1",
            },
            "discovery": {
                "mechanism": "github_check_run",
                "check_run_id": (
                    latest.get("id")
                    if isinstance(latest.get("id"), int)
                    else None
                ),
                "app_id": (
                    latest.get("app_id")
                    if isinstance(latest.get("app_id"), int)
                    else None
                ),
                "app_slug": str(latest.get("app_slug") or ""),
                "source_evidence_id": str(
                    github_checks.get("id") or "ev_github_checks"
                ),
            },
            "capabilities": sorted(adapter.capabilities),
            "entitlement": {"state": "UNKNOWN"},
            "execution": {
                "observed": True,
                "check_name": latest_check_name,
                "status": latest.get("status"),
                "conclusion": latest.get("conclusion"),
                "started_at": latest.get("started_at"),
                "completed_at": latest.get("completed_at"),
            },
            "coverage": {
                "target_commit_sha": target_sha,
                "target_binding": "ATTACHED",
                "scan_scope": "OBSERVED" if scope else "UNKNOWN",
                "scope": scope,
            },
            "inventory": {
                "access_state": "UNAVAILABLE",
                "reason": "provider_inventory_not_connected",
                "items": [],
            },
            "enforcement": {
                "state": enforcement_state,
                **({"contexts": contexts} if contexts else {}),
            },
            "evidence_gaps": sorted(
                {
                    "provider_entitlement",
                    "provider_issue_inventory",
                    *(
                        {"provider_capabilities"}
                        if adapter.adapter_id == "generic-github-check/v1"
                        else set()
                    ),
                }
            ),
            "current_baseline_requirements": [],
        }
        validate_document("provider-state.v1", state)

        digest = hashlib.sha256(provider_id.encode("utf-8")).hexdigest()[:12]
        evidence = {
            "schema_version": "evidence/v1",
            "id": f"ev_provider_{digest}",
            "kind": "provider_state",
            "source": {
                "provider": adapter.provider_id,
                "mechanism": "github-check-run",
                "collector": "provider-discovery/v1",
            },
            "subject": {"type": "provider", "identifier": provider_id},
            "observation": state,
            "snapshot": {
                "repository": repository,
                "target_commit_sha": target_sha,
            },
            "collected_at": str(github_checks.get("collected_at")),
            "visibility": {
                "completeness": "partial",
                "permission_limited": False,
                "retention_limited": False,
            },
            "redactions": [],
        }
        sanitized = sanitize_evidence(evidence)
        validate_document("evidence.v1", sanitized)
        output.append(sanitized)
    return output


def collect_provider_discovery(
    github_checks: Mapping[str, Any],
) -> dict[str, Any]:
    observation = github_checks.get("observation")
    access_state = (
        str(observation.get("access_state", "UNKNOWN_ERROR"))
        if isinstance(observation, Mapping)
        else "UNKNOWN_ERROR"
    )
    states = (
        collect_provider_states(
            github_checks,
            required_checks=None,
        )
        if access_state == "AVAILABLE"
        else []
    )

    repository, target_sha = _snapshot_context(github_checks)
    permission_limited = access_state in {"UNKNOWN_PERMISSION", "AUTH_FAILED"}

    item = {
        "schema_version": "evidence/v1",
        "id": "ev_provider_discovery",
        "kind": "provider_state",
        "source": {
            "provider": "github",
            "mechanism": "check-run-discovery",
            "collector": "provider-discovery/v1",
        },
        "subject": {"type": "repository", "identifier": repository},
        "observation": {
            "access_state": access_state,
            "detected_provider_ids": sorted(
                str(state["subject"]["identifier"])
                for state in states
            ),
            "source_evidence_id": str(
                github_checks.get("id") or "ev_github_checks"
            ),
        },
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_sha,
        },
        "collected_at": str(github_checks.get("collected_at")),
        "visibility": {
            "completeness": (
                "complete" if access_state == "AVAILABLE" else "unknown"
            ),
            "permission_limited": permission_limited,
            "retention_limited": False,
        },
        "redactions": [],
    }
    sanitized = sanitize_evidence(item)
    validate_document("evidence.v1", sanitized)
    return sanitized


def provider_summaries(
    evidence: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in evidence:
        subject = item.get("subject")
        observation = item.get("observation")
        if (
            not isinstance(subject, Mapping)
            or subject.get("type") != "provider"
            or not isinstance(observation, Mapping)
        ):
            continue
        summary = dict(observation)
        validate_document("provider-state.v1", summary)
        summaries.append(summary)
    return sorted(
        summaries,
        key=lambda item: str(item["provider"]["id"]),
    )

