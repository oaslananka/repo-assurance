from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from repo_assurance.core.schema import validate_document


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _result(
    control_id: str,
    state: str,
    subject: Mapping[str, Any],
    evidence_ids: Iterable[str],
    *,
    reason: str | None = None,
    candidates: Iterable[str] = (),
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": dict(subject),
        "evidence_ids": sorted({str(value) for value in evidence_ids}),
        "candidate_finding_ids": sorted({str(value) for value in candidates}),
        "evaluated_at": _now(),
    }
    if reason:
        item["reason"] = reason
    validate_document("control-result.v1", item)
    return item


def _provider_items(
    evidence: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return [
        item
        for item in evidence
        if item.get("kind") == "provider_state"
        and isinstance(item.get("subject"), Mapping)
        and item["subject"].get("type") == "provider"
    ]


def _discovery(
    evidence: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    return next(
        (item for item in evidence if item.get("id") == "ev_provider_discovery"),
        None,
    )


def _access_state(discovery: Mapping[str, Any] | None) -> str:
    if discovery is None:
        return "UNAVAILABLE"
    observation = discovery.get("observation")
    if not isinstance(observation, Mapping):
        return "UNKNOWN_ERROR"
    return str(observation.get("access_state", "UNKNOWN_ERROR"))


def _access_result(
    control_id: str,
    discovery: Mapping[str, Any] | None,
) -> dict[str, Any]:
    access = _access_state(discovery)
    state = {
        "UNKNOWN_PERMISSION": "UNKNOWN_PERMISSION",
        "AUTH_FAILED": "UNKNOWN_PERMISSION",
        "UNKNOWN_ERROR": "UNKNOWN_ERROR",
        "UNAVAILABLE": "UNAVAILABLE",
    }.get(access, "INCONCLUSIVE")
    evidence_ids = (
        [str(discovery["id"])]
        if discovery is not None and discovery.get("id")
        else []
    )
    subject = (
        dict(discovery["subject"])
        if discovery is not None and isinstance(discovery.get("subject"), Mapping)
        else {"type": "repository", "identifier": "unknown"}
    )
    return _result(
        control_id,
        state,
        subject,
        evidence_ids,
        reason=f"provider_discovery:{access}",
    )


def _inventory_state(
    provider_id: str,
    state: Mapping[str, Any],
    evidence_id: str,
) -> tuple[str, str | None]:
    inventory = state.get("inventory")
    if not isinstance(inventory, Mapping):
        return "UNKNOWN_ERROR", "provider_inventory_invalid"
    access = str(inventory.get("access_state", "UNKNOWN_ERROR"))
    if access == "AVAILABLE":
        return "PASS", "provider_inventory_visible"
    if access == "UNKNOWN_PERMISSION":
        return "UNKNOWN_PERMISSION", "provider_inventory_permission_unknown"
    if access == "UNKNOWN_ERROR":
        return "UNKNOWN_ERROR", "provider_inventory_error"
    return "UNAVAILABLE", "provider_inventory_unavailable"


def _open_items(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    inventory = state.get("inventory")
    if not isinstance(inventory, Mapping):
        return []
    items = inventory.get("items")
    if not isinstance(items, list):
        return []
    return [
        item
        for item in items
        if isinstance(item, Mapping)
        and str(item.get("state", "open")).lower() == "open"
    ]


def _issue_result(
    provider_id: str,
    item: Mapping[str, Any],
    evidence_id: str,
) -> dict[str, Any]:
    upstream_id = str(
        item.get("upstream_id")
        or item.get("id")
        or "unknown"
    )
    kind = str(item.get("kind") or "provider_issue")
    qualifiers: dict[str, Any] = {"provider": provider_id}
    for key in ("package", "ecosystem", "severity"):
        if item.get(key):
            qualifiers[key] = str(item[key])

    if kind == "dependency_vulnerability" and upstream_id.upper().startswith("GHSA-"):
        subject = {
            "type": "dependency",
            "identifier": upstream_id.upper(),
            "qualifiers": qualifiers,
        }
    else:
        subject = {
            "type": "provider_check",
            "identifier": f"{provider_id}:{upstream_id}",
            "qualifiers": {
                **qualifiers,
                "kind": kind,
            },
        }

    safe_id = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_"
        for ch in upstream_id
    )
    return _result(
        "PROV-003",
        "FINDING",
        subject,
        [evidence_id],
        reason=f"open_provider_issue:{provider_id}:{upstream_id}",
        candidates=[f"candidate_PROV-003_{provider_id}_{safe_id}"],
    )


def evaluate_providers(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    providers = _provider_items(evidence)
    discovery = _discovery(evidence)

    if not providers:
        if _access_state(discovery) == "AVAILABLE":
            subject = (
                dict(discovery["subject"])
                if discovery is not None and isinstance(discovery.get("subject"), Mapping)
                else {"type": "repository", "identifier": "unknown"}
            )
            ids = [str(discovery["id"])] if discovery and discovery.get("id") else []
            return [
                _result(
                    control_id,
                    "NOT_ENABLED",
                    subject,
                    ids,
                    reason="no_external_provider_detected",
                )
                for control_id in ("PROV-001", "PROV-002", "PROV-003")
            ]
        return [
            _access_result(control_id, discovery)
            for control_id in ("PROV-001", "PROV-002", "PROV-003")
        ]

    results: list[dict[str, Any]] = []
    for item in sorted(
        providers,
        key=lambda value: str(value.get("subject", {}).get("identifier", "")),
    ):
        evidence_id = str(item.get("id"))
        subject = (
            dict(item["subject"])
            if isinstance(item.get("subject"), Mapping)
            else {"type": "provider", "identifier": "unknown"}
        )
        state = item.get("observation")
        if not isinstance(state, Mapping):
            for control_id in ("PROV-001", "PROV-002", "PROV-003"):
                results.append(
                    _result(
                        control_id,
                        "UNKNOWN_ERROR",
                        subject,
                        [evidence_id],
                        reason="provider_state_invalid",
                    )
                )
            continue

        provider = state.get("provider")
        provider_id = (
            str(provider.get("id"))
            if isinstance(provider, Mapping) and provider.get("id")
            else str(subject.get("identifier", "unknown"))
        )

        execution = state.get("execution")
        conclusion = (
            str(execution.get("conclusion") or "").lower()
            if isinstance(execution, Mapping)
            else ""
        )
        status = (
            str(execution.get("status") or "").lower()
            if isinstance(execution, Mapping)
            else ""
        )
        if status != "completed":
            execution_result = _result(
                "PROV-001",
                "INCONCLUSIVE",
                subject,
                [evidence_id],
                reason=f"provider_execution_incomplete:{provider_id}",
            )
        elif conclusion == "success":
            execution_result = _result(
                "PROV-001",
                "PASS",
                subject,
                [evidence_id],
                reason=f"provider_execution_success:{provider_id}",
            )
        elif conclusion in {"failure", "timed_out", "startup_failure", "action_required"}:
            execution_result = _result(
                "PROV-001",
                "FINDING",
                subject,
                [evidence_id],
                reason=f"provider_execution_failed:{provider_id}:{conclusion}",
                candidates=[f"candidate_PROV-001_{provider_id}_execution_failure"],
            )
        else:
            execution_result = _result(
                "PROV-001",
                "INCONCLUSIVE",
                subject,
                [evidence_id],
                reason=f"provider_execution_non_success:{provider_id}:{conclusion or 'unknown'}",
            )
        results.append(execution_result)

        inventory_state, inventory_reason = _inventory_state(
            provider_id,
            state,
            evidence_id,
        )
        results.append(
            _result(
                "PROV-002",
                inventory_state,
                subject,
                [evidence_id],
                reason=inventory_reason,
            )
        )

        if inventory_state != "PASS":
            results.append(
                _result(
                    "PROV-003",
                    inventory_state,
                    subject,
                    [evidence_id],
                    reason=inventory_reason,
                )
            )
            continue

        open_items = _open_items(state)
        if not open_items:
            results.append(
                _result(
                    "PROV-003",
                    "PASS",
                    subject,
                    [evidence_id],
                    reason="provider_inventory_visible_no_open_items",
                )
            )
            continue

        results.extend(
            _issue_result(provider_id, issue, evidence_id)
            for issue in open_items
        )

    return results

