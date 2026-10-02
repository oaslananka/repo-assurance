from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from repo_assurance.core.schema import validate_document


@dataclass(frozen=True)
class RepositoryCapabilities:
    values: Mapping[str, bool]

    def has(self, capability: str) -> bool:
        return bool(self.values.get(capability, False))


def _budgets_for_mode(mode: str) -> dict[str, object]:
    budgets = {
        "quick": {
            "github": {"max_runs_per_workflow": 30, "max_history_days": 30},
            "current_baseline": {"max_external_lookups": 5},
        },
        "standard": {
            "github": {"max_runs_per_workflow": 100, "max_history_days": 90},
            "current_baseline": {"max_external_lookups": 20},
        },
        "deep": {
            "github": {"max_runs_per_workflow": 250, "max_history_days": 180},
            "current_baseline": {"max_external_lookups": 50},
        },
    }
    try:
        return budgets[mode]
    except KeyError as exc:
        raise ValueError(f"unsupported audit mode: {mode}") from exc


def _applicability(
    control: Mapping[str, object],
    capabilities: RepositoryCapabilities,
    repository_type: str | None,
) -> dict[str, object]:
    applicability = control.get("applicability")
    if not isinstance(applicability, Mapping):
        return {
            "control_id": str(control["id"]),
            "applicable": False,
            "reason": "invalid_applicability_metadata",
        }

    excluded = [str(item) for item in applicability.get("excluded_repository_types", [])]
    if repository_type and repository_type in excluded:
        return {
            "control_id": str(control["id"]),
            "applicable": False,
            "reason": f"excluded_repository_type:{repository_type}",
        }

    required = [str(item) for item in applicability.get("all_capabilities", [])]
    missing = sorted(cap for cap in required if not capabilities.has(cap))
    if missing:
        return {
            "control_id": str(control["id"]),
            "applicable": False,
            "reason": f"missing_capabilities:{','.join(missing)}",
        }

    any_caps = [str(item) for item in applicability.get("any_capabilities", [])]
    if any_caps and not any(capabilities.has(cap) for cap in any_caps):
        return {
            "control_id": str(control["id"]),
            "applicable": False,
            "reason": f"missing_any_capability:{','.join(sorted(any_caps))}",
        }

    return {"control_id": str(control["id"]), "applicable": True}


def build_audit_plan(
    *,
    catalog: Sequence[Mapping[str, object]],
    capabilities: RepositoryCapabilities,
    repository: Mapping[str, object],
    snapshot: Mapping[str, object],
    mode: str,
) -> dict[str, object]:
    budgets = _budgets_for_mode(mode)
    repository_type = repository.get("repository_type")
    if repository_type is not None:
        repository_type = str(repository_type)

    controls = [
        _applicability(control, capabilities, repository_type)
        for control in sorted(catalog, key=lambda item: str(item["id"]))
    ]

    canonical_repository = {
        "owner": str(repository["owner"]),
        "name": str(repository["name"]),
        "full_name": str(repository["full_name"]),
    }
    canonical_snapshot = {
        "target_branch": str(snapshot["target_branch"]),
        "target_commit_sha": str(snapshot["target_commit_sha"]),
    }
    plan = {
        "schema_version": "audit-plan/v1",
        "audit_id": f"audit_{canonical_snapshot['target_commit_sha'][:12]}_{mode}",
        "mode": mode,
        "repository": canonical_repository,
        "snapshot": canonical_snapshot,
        "capabilities": dict(sorted(capabilities.values.items())),
        "controls": controls,
        "budgets": budgets,
    }
    validate_document("audit-plan.v1", plan)
    return plan
