from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


def _observation(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = item.get("observation")
    return value if isinstance(value, Mapping) else None


def _access_available(item: Mapping[str, Any]) -> bool:
    observation = _observation(item)
    return bool(observation and observation.get("access_state") == "AVAILABLE")


def _permission_limited(item: Mapping[str, Any]) -> bool:
    observation = _observation(item)
    if observation and observation.get("access_state") in {"UNKNOWN_PERMISSION", "AUTH_FAILED"}:
        return True
    visibility = item.get("visibility")
    return bool(
        isinstance(visibility, Mapping)
        and visibility.get("permission_limited")
    )


def _by_id(
    evidence: Sequence[Mapping[str, Any]],
    evidence_id: str,
) -> Mapping[str, Any] | None:
    return next(
        (item for item in evidence if item.get("id") == evidence_id),
        None,
    )


def _normalize_app_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _required_checks(
    governance: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], bool, bool]:
    requirements: dict[tuple[str, int | None], dict[str, Any]] = {}
    permission_limited = any(_permission_limited(item) for item in governance)

    default_branch = _by_id(governance, "ev_github_default_branch")
    rulesets = _by_id(governance, "ev_github_rulesets")
    policy_complete = bool(
        default_branch
        and rulesets
        and _access_available(default_branch)
        and _access_available(rulesets)
    )

    if default_branch and _access_available(default_branch):
        observation = _observation(default_branch) or {}
        details = observation.get("required_status_check_details")
        if isinstance(details, list):
            for item in details:
                if not isinstance(item, Mapping) or not item.get("context"):
                    continue
                context = str(item["context"])
                app_id = _normalize_app_id(item.get("app_id"))
                requirements[(context, app_id)] = {
                    "context": context,
                    "app_id": app_id,
                }
        else:
            for value in observation.get("required_status_checks", []):
                if value:
                    context = str(value)
                    requirements[(context, None)] = {
                        "context": context,
                        "app_id": None,
                    }

    if rulesets and _access_available(rulesets):
        observation = _observation(rulesets) or {}
        raw_rulesets = observation.get("rulesets")
        if isinstance(raw_rulesets, list):
            for ruleset in raw_rulesets:
                if not isinstance(ruleset, Mapping):
                    continue
                if ruleset.get("enforcement") != "active":
                    continue
                if ruleset.get("target") != "branch":
                    continue
                conditions = ruleset.get("conditions")
                if not isinstance(conditions, Mapping):
                    continue
                ref_name = conditions.get("ref_name")
                if not isinstance(ref_name, Mapping):
                    continue
                includes = ref_name.get("include") or []
                excludes = ref_name.get("exclude") or []
                if "~DEFAULT_BRANCH" not in includes or "~DEFAULT_BRANCH" in excludes:
                    continue
                rules = ruleset.get("rules")
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    if not isinstance(rule, Mapping):
                        continue
                    if rule.get("type") != "required_status_checks":
                        continue
                    parameters = rule.get("parameters")
                    if not isinstance(parameters, Mapping):
                        continue
                    required = parameters.get("required_status_checks")
                    if not isinstance(required, list):
                        continue
                    for check in required:
                        if not isinstance(check, Mapping) or not check.get("context"):
                            continue
                        context = str(check["context"])
                        app_id = _normalize_app_id(
                            check.get("integration_id", check.get("app_id"))
                        )
                        requirements[(context, app_id)] = {
                            "context": context,
                            "app_id": app_id,
                        }

    ordered = sorted(
        requirements.values(),
        key=lambda item: (
            str(item["context"]),
            -1 if item["app_id"] is None else int(item["app_id"]),
        ),
    )
    return ordered, policy_complete, permission_limited


def required_check_names(
    governance: Sequence[Mapping[str, Any]],
) -> set[str]:
    requirements, _, _ = _required_checks(governance)
    return {str(item["context"]) for item in requirements}


def resolve_required_gate_mapping(
    governance: Sequence[Mapping[str, Any]],
    history: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    requirements, policy_complete, permission_limited = _required_checks(governance)
    checks = _by_id(governance, "ev_github_checks")

    if checks is None or not _access_available(checks):
        check_runs: list[Mapping[str, Any]] = []
        checks_available = False
        if checks is not None:
            permission_limited = permission_limited or _permission_limited(checks)
    else:
        observation = _observation(checks) or {}
        raw = observation.get("check_runs")
        check_runs = [
            item for item in raw if isinstance(item, Mapping)
        ] if isinstance(raw, list) else []
        checks_available = isinstance(raw, list)

    run_to_workflows: dict[int, list[dict[str, Any]]] = {}
    for item in history:
        observation = _observation(item)
        if not observation or observation.get("access_state") not in {"AVAILABLE", "PARTIAL"}:
            permission_limited = permission_limited or _permission_limited(item)
            continue
        workflow_id = observation.get("workflow_id")
        if workflow_id is None:
            continue
        subject = item.get("subject")
        workflow_path = (
            str(subject.get("identifier"))
            if isinstance(subject, Mapping) and subject.get("identifier")
            else str(workflow_id)
        )
        workflow_name = observation.get("workflow_name")
        runs = observation.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, Mapping) or not isinstance(run.get("id"), int):
                continue
            run_id = int(run["id"])
            run_to_workflows.setdefault(run_id, []).append({
                "workflow_id": str(workflow_id),
                "workflow_name": str(workflow_name) if workflow_name is not None else None,
                "workflow_path": workflow_path,
            })

    mappings: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    required_workflow_ids: set[str] = set()

    for requirement in requirements:
        context = str(requirement["context"])
        app_id = requirement["app_id"]
        matching_name = [
            item
            for item in check_runs
            if item.get("name") == context
        ]
        if app_id is not None:
            matching = [
                item
                for item in matching_name
                if _normalize_app_id(item.get("app_id")) == app_id
            ]
            if matching_name and not matching:
                unresolved.append({
                    "context": context,
                    "app_id": app_id,
                    "reason": "required_check_not_produced_by_expected_app",
                })
                continue
        else:
            matching = matching_name

        if not matching:
            unresolved.append({
                "context": context,
                "app_id": app_id,
                "reason": (
                    "required_check_runs_unavailable"
                    if not checks_available
                    else "required_check_not_observed"
                ),
            })
            continue

        workflow_matches: dict[str, dict[str, Any]] = {}
        check_run_ids: set[int] = set()
        job_ids: set[int] = set()
        workflow_run_ids: set[int] = set()
        unlinked = False

        for check_run in matching:
            check_id = check_run.get("id")
            if isinstance(check_id, int):
                check_run_ids.add(check_id)
            job_id = check_run.get("job_id")
            if isinstance(job_id, int):
                job_ids.add(job_id)
            run_id = check_run.get("workflow_run_id")
            if not isinstance(run_id, int):
                unlinked = True
                continue
            workflow_run_ids.add(run_id)
            matches = run_to_workflows.get(run_id, [])
            if not matches:
                unlinked = True
                continue
            for workflow in matches:
                workflow_matches[str(workflow["workflow_id"])] = workflow

        if len(workflow_matches) > 1:
            unresolved.append({
                "context": context,
                "app_id": app_id,
                "reason": "required_check_maps_to_multiple_workflows",
                "workflow_ids": sorted(workflow_matches),
            })
            continue
        if not workflow_matches or unlinked:
            unresolved.append({
                "context": context,
                "app_id": app_id,
                "reason": "required_check_workflow_link_unresolved",
            })
            continue

        workflow = next(iter(workflow_matches.values()))
        workflow_id = str(workflow["workflow_id"])
        required_workflow_ids.add(workflow_id)
        mappings.append({
            "context": context,
            "app_id": app_id,
            "check_run_ids": sorted(check_run_ids),
            "job_ids": sorted(job_ids),
            "workflow_run_ids": sorted(workflow_run_ids),
            "workflow_id": workflow_id,
            "workflow_name": workflow["workflow_name"],
            "workflow_path": workflow["workflow_path"],
        })

    complete = bool(
        policy_complete
        and (not requirements or checks_available)
        and not unresolved
    )
    return {
        "complete": complete,
        "permission_limited": permission_limited,
        "required_workflow_ids": sorted(required_workflow_ids),
        "mappings": sorted(
            mappings,
            key=lambda item: (
                str(item["context"]),
                str(item["workflow_id"]),
            ),
        ),
        "unresolved": sorted(
            unresolved,
            key=lambda item: (
                str(item.get("context", "")),
                str(item.get("reason", "")),
            ),
        ),
    }


def build_required_gate_mapping_evidence(
    *,
    repository: str,
    target_commit_sha: str,
    governance: Sequence[Mapping[str, Any]],
    history: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    mapping = resolve_required_gate_mapping(governance, history)
    source_ids = sorted({
        str(item["id"])
        for item in [*governance, *history]
        if item.get("id")
    })
    item = {
        "schema_version": "evidence/v1",
        "id": "ev_required_gate_mapping",
        "kind": "inference",
        "source": {
            "provider": "repo-assurance",
            "mechanism": "correlation",
            "collector": "required-gate-mapping/v1",
        },
        "subject": {"type": "repository", "identifier": repository},
        "observation": {
            **mapping,
            "source_evidence_ids": source_ids,
        },
        "snapshot": {
            "repository": repository,
            "target_commit_sha": target_commit_sha,
        },
        "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "visibility": {
            "completeness": (
                "complete"
                if mapping["complete"]
                else ("unknown" if mapping["permission_limited"] else "partial")
            ),
            "permission_limited": bool(mapping["permission_limited"]),
            "retention_limited": False,
        },
        "redactions": [],
    }
    validate_document("evidence.v1", item)
    return item

