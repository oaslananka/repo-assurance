from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence


_DOMAIN_PREFIXES: tuple[tuple[str, str], ...] = (
    ("CI-STATIC-", "ci_static"),
    ("CI-OPS-", "ci_history"),
    ("GH-GOV-", "github_governance"),
    ("GH-SEC-", "github_security"),
    ("HYGIENE-", "workspace_hygiene"),
    ("CURRENT-", "current_baseline"),
    ("SNAP-", "snapshot"),
    ("REPO-", "repository"),
    ("DEP-", "dependencies"),
    ("PROV-", "external_providers"),
)

_VERIFIED_STATES = {"PASS", "FINDING", "NOT_ENABLED"}
_UNAVAILABLE_STATES = {"UNAVAILABLE", "UNKNOWN_ERROR"}
_PARTIAL_STATES = {"INCONCLUSIVE"}


def _domain_for_control(control_id: str) -> str:
    for prefix, domain in _DOMAIN_PREFIXES:
        if control_id.startswith(prefix):
            return domain
    return "other"


def _evidence_visibility_is_partial(
    result_items: Sequence[Mapping[str, Any]],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> bool:
    if not evidence_by_id:
        return False
    for result in result_items:
        for evidence_id in result.get("evidence_ids", []):
            item = evidence_by_id.get(str(evidence_id))
            if not item:
                continue
            visibility = item.get("visibility")
            if not isinstance(visibility, Mapping):
                continue
            if visibility.get("completeness") in {"partial", "unknown"}:
                return True
            if visibility.get("retention_limited"):
                return True
    return False


def compute_domain_coverage(
    *,
    audit_plan: Mapping[str, Any],
    control_results: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, str]:
    """Compute evidence coverage without conflating findings with verification failure."""
    planned_by_domain: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for entry in audit_plan.get("controls", []):
        if not isinstance(entry, Mapping):
            continue
        control_id = str(entry.get("control_id", ""))
        planned_by_domain[_domain_for_control(control_id)].append(entry)

    results_by_control: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in control_results:
        results_by_control[str(item.get("control_id", ""))].append(item)

    evidence_by_id = {
        str(item.get("id")): item
        for item in evidence
        if isinstance(item, Mapping) and item.get("id") is not None
    }

    coverage: dict[str, str] = {}
    for domain in sorted(planned_by_domain):
        entries = planned_by_domain[domain]
        applicable_ids = {
            str(entry.get("control_id"))
            for entry in entries
            if entry.get("applicable") is True
        }
        if not applicable_ids:
            coverage[domain] = "NOT_APPLICABLE"
            continue

        domain_results = [
            item
            for control_id in sorted(applicable_ids)
            for item in results_by_control.get(control_id, [])
        ]
        controls_with_results = {
            str(item.get("control_id")) for item in domain_results
        }
        missing_controls = applicable_ids - controls_with_results

        if not domain_results:
            coverage[domain] = "UNAVAILABLE"
            continue

        states = [str(item.get("state", "UNKNOWN_ERROR")) for item in domain_results]
        if states and all(state == "UNKNOWN_PERMISSION" for state in states) and not missing_controls:
            coverage[domain] = "UNKNOWN_PERMISSION"
            continue

        has_verified = any(state in _VERIFIED_STATES for state in states)
        has_unknown_permission = any(state == "UNKNOWN_PERMISSION" for state in states)
        has_partial_state = any(state in _PARTIAL_STATES for state in states)
        has_unavailable_state = any(state in _UNAVAILABLE_STATES for state in states)
        visibility_partial = _evidence_visibility_is_partial(domain_results, evidence_by_id)

        if (
            missing_controls
            or has_unknown_permission
            or has_partial_state
            or visibility_partial
            or (has_unavailable_state and has_verified)
        ):
            coverage[domain] = "PARTIAL"
        elif has_unavailable_state and not has_verified:
            coverage[domain] = "UNAVAILABLE"
        else:
            coverage[domain] = "VERIFIED"

    return coverage
