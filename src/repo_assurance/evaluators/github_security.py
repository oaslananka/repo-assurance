from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence

from repo_assurance.core.schema import validate_document


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find(
    evidence: Sequence[Mapping[str, Any]],
    evidence_id: str,
) -> Mapping[str, Any] | None:
    return next(
        (item for item in evidence if item.get("id") == evidence_id),
        None,
    )


def _observation(
    item: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    if not item:
        return {}
    value = item.get("observation")
    return value if isinstance(value, Mapping) else {}


def _access_state(item: Mapping[str, Any] | None) -> str:
    if item is None:
        return "UNAVAILABLE"
    observation = _observation(item)
    return str(observation.get("access_state", "UNKNOWN_ERROR"))


def _state_for_access(access: str) -> str:
    if access in {"UNKNOWN_PERMISSION", "AUTH_FAILED"}:
        return "UNKNOWN_PERMISSION"
    if access == "UNKNOWN_ERROR":
        return "UNKNOWN_ERROR"
    if access == "UNAVAILABLE":
        return "UNAVAILABLE"
    return "INCONCLUSIVE"


def _repo_subject(
    evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    for item in evidence:
        subject = item.get("subject")
        if isinstance(subject, Mapping) and subject.get("type") == "repository":
            return dict(subject)
    return {"type": "repository", "identifier": "unknown"}


def _target_sha(
    evidence: Sequence[Mapping[str, Any]],
) -> str | None:
    for item in evidence:
        snapshot = item.get("snapshot")
        if isinstance(snapshot, Mapping) and snapshot.get("target_commit_sha"):
            return str(snapshot["target_commit_sha"])
    return None


def _result(
    control_id: str,
    state: str,
    subject: Mapping[str, Any],
    evidence_ids: Iterable[str],
    *,
    reason: str | None = None,
    candidates: Iterable[str] = (),
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": dict(subject),
        "evidence_ids": sorted({str(item) for item in evidence_ids}),
        "candidate_finding_ids": sorted({str(item) for item in candidates}),
        "evaluated_at": _now(),
    }
    if reason:
        result["reason"] = reason
    validate_document("control-result.v1", result)
    return result


def _access_result(
    *,
    control_id: str,
    item: Mapping[str, Any] | None,
    subject: Mapping[str, Any],
    reason_prefix: str,
) -> dict[str, Any]:
    access = _access_state(item)
    evidence_ids = [str(item["id"])] if item and item.get("id") else []
    return _result(
        control_id,
        _state_for_access(access),
        subject,
        evidence_ids,
        reason=f"{reason_prefix}:{access}",
    )


def _open_alerts(item: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    observation = _observation(item)
    raw = observation.get("alerts")
    if not isinstance(raw, list):
        return []
    return [
        alert
        for alert in raw
        if isinstance(alert, Mapping)
        and str(alert.get("state", "")).lower() == "open"
    ]


def _evaluate_alert_surface(
    *,
    item: Mapping[str, Any] | None,
    control_id: str,
    repository_subject: Mapping[str, Any],
    reason_prefix: str,
    empty_alert_reason: str,
    build_finding: Callable[[Mapping[str, Any], Sequence[str]], dict[str, Any]],
    evidence_ids: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    ids = list(evidence_ids or [])
    if not ids and item and item.get("id"):
        ids = [str(item["id"])]

    access = _access_state(item)
    if access != "AVAILABLE":
        return [
            _result(
                control_id,
                _state_for_access(access),
                repository_subject,
                ids,
                reason=f"{reason_prefix}:{access}",
            )
        ]

    alerts = sorted(
        _open_alerts(item),
        key=lambda alert: int(alert.get("number") or 0),
    )
    if not alerts:
        return [
            _result(
                control_id,
                "PASS",
                repository_subject,
                ids,
                reason=empty_alert_reason,
            )
        ]
    return [build_finding(alert, ids) for alert in alerts]


def _code_scanning_alert_finding(
    alert: Mapping[str, Any],
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    number = alert.get("number")
    rule = alert.get("rule")
    tool = alert.get("tool")
    qualifiers: dict[str, Any] = {}
    if isinstance(tool, Mapping) and tool.get("name"):
        qualifiers["tool"] = str(tool["name"])
    if isinstance(rule, Mapping):
        if rule.get("id"):
            qualifiers["rule_id"] = str(rule["id"])
        if rule.get("security_severity_level"):
            qualifiers["security_severity_level"] = str(
                rule["security_severity_level"]
            )
    return _result(
        "GH-SEC-002",
        "FINDING",
        {
            "type": "provider_check",
            "identifier": f"github-code-scanning:{number}",
            "qualifiers": qualifiers,
        },
        evidence_ids,
        reason=f"open_code_scanning_alert:{number}",
        candidates=[f"candidate_GH-SEC-002_alert_{number}"],
    )


def _secret_scanning_alert_finding(
    alert: Mapping[str, Any],
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    number = alert.get("number")
    secret_type = alert.get("secret_type")
    qualifiers = (
        {"secret_type": str(secret_type)}
        if secret_type
        else {}
    )
    return _result(
        "GH-SEC-003",
        "FINDING",
        {
            "type": "provider_check",
            "identifier": f"github-secret-scanning:{number}",
            "qualifiers": qualifiers,
        },
        evidence_ids,
        reason=f"open_secret_scanning_alert:{number}",
        candidates=[f"candidate_GH-SEC-003_alert_{number}"],
    )


def _dependabot_alert_finding(
    alert: Mapping[str, Any],
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    number = alert.get("number")
    dependency = alert.get("dependency")
    advisory = alert.get("security_advisory")
    ghsa_id = (
        advisory.get("ghsa_id")
        if isinstance(advisory, Mapping)
        else None
    )
    identifier = (
        str(ghsa_id)
        if ghsa_id
        else f"github-dependabot:{number}"
    )
    qualifiers: dict[str, Any] = {}
    if isinstance(dependency, Mapping):
        for source_key, target_key in (
            ("package", "package"),
            ("manifest_path", "manifest_path"),
            ("scope", "scope"),
            ("ecosystem", "ecosystem"),
        ):
            value = dependency.get(source_key)
            if value:
                qualifiers[target_key] = str(value)

    return _result(
        "DEP-003",
        "FINDING",
        {
            "type": "dependency",
            "identifier": identifier,
            "qualifiers": qualifiers,
        },
        evidence_ids,
        reason=f"open_dependabot_alert:{number}",
        candidates=[f"candidate_DEP-003_alert_{number}"],
    )


def _evaluate_code_scanning_coverage(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    analyses = _find(evidence, "ev_github_code_scanning_analyses")
    access = _access_state(analyses)
    if access != "AVAILABLE":
        return _access_result(
            control_id="GH-SEC-001",
            item=analyses,
            subject=subject,
            reason_prefix="code_scanning_analysis_visibility",
        )

    target_sha = _target_sha(evidence)
    observation = _observation(analyses)
    raw = observation.get("analyses")
    analysis_items = [
        item for item in raw if isinstance(item, Mapping)
    ] if isinstance(raw, list) else []

    target_items = [
        item
        for item in analysis_items
        if target_sha and item.get("commit_sha") == target_sha
    ]
    successful = [
        item
        for item in target_items
        if not str(item.get("error") or "").strip()
    ]
    failed = [
        item
        for item in target_items
        if str(item.get("error") or "").strip()
    ]
    evidence_ids = [str(analyses["id"])]

    if successful:
        return _result(
            "GH-SEC-001",
            "PASS",
            subject,
            evidence_ids,
            reason=f"code_scanning_target_covered:{len(successful)}",
        )

    if failed:
        return _result(
            "GH-SEC-001",
            "FINDING",
            subject,
            evidence_ids,
            reason=f"code_scanning_target_analysis_error:{len(failed)}",
            candidates=["candidate_GH-SEC-001_target_analysis_error"],
        )

    if analysis_items and target_sha:
        return _result(
            "GH-SEC-001",
            "FINDING",
            subject,
            evidence_ids,
            reason=f"code_scanning_target_not_covered:{target_sha}",
            candidates=["candidate_GH-SEC-001_target_not_covered"],
        )

    return _result(
        "GH-SEC-001",
        "NOT_ENABLED",
        subject,
        evidence_ids,
        reason="code_scanning_analysis_not_observed",
    )


def _evaluate_code_scanning_alerts(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return _evaluate_alert_surface(
        item=_find(evidence, "ev_github_code_scanning_alerts"),
        control_id="GH-SEC-002",
        repository_subject=subject,
        reason_prefix="code_scanning_alert_visibility",
        empty_alert_reason="code_scanning_alerts_visible:no_open_alerts",
        build_finding=_code_scanning_alert_finding,
    )


def _evaluate_secret_scanning(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> list[dict[str, Any]]:
    repository = _find(evidence, "ev_github_repository")
    repository_access = _access_state(repository)
    if repository_access != "AVAILABLE":
        return [
            _access_result(
                control_id="GH-SEC-003",
                item=repository,
                subject=subject,
                reason_prefix="repository_security_configuration_visibility",
            )
        ]

    alerts = _find(evidence, "ev_github_secret_scanning_alerts")
    evidence_ids = [
        str(item["id"])
        for item in (repository, alerts)
        if item and item.get("id")
    ]

    security = _observation(repository).get("security_and_analysis")
    if not isinstance(security, Mapping):
        return [
            _result(
                "GH-SEC-003",
                "INCONCLUSIVE",
                subject,
                evidence_ids,
                reason="security_configuration_not_exposed",
            )
        ]

    required = {
        "secret_scanning": security.get("secret_scanning"),
        "secret_scanning_push_protection": security.get(
            "secret_scanning_push_protection"
        ),
    }
    disabled = [
        f"{key}={value}"
        for key, value in required.items()
        if value is not None and str(value).lower() != "enabled"
    ]
    missing = sorted(
        key for key, value in required.items() if value is None
    )

    if disabled:
        return [
            _result(
                "GH-SEC-003",
                "FINDING",
                subject,
                evidence_ids,
                reason=",".join(disabled),
                candidates=["candidate_GH-SEC-003_secret_scanning_configuration"],
            )
        ]

    if missing:
        return [
            _result(
                "GH-SEC-003",
                "INCONCLUSIVE",
                subject,
                evidence_ids,
                reason=f"security_configuration_not_exposed:{','.join(missing)}",
            )
        ]

    return _evaluate_alert_surface(
        item=alerts,
        control_id="GH-SEC-003",
        repository_subject=subject,
        reason_prefix="secret_scanning_alert_visibility",
        empty_alert_reason="secret_scanning_enabled_and_alerts_visible:no_open_alerts",
        build_finding=_secret_scanning_alert_finding,
        evidence_ids=evidence_ids,
    )


def _evaluate_dependency_sbom(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    sbom_evidence = _find(evidence, "ev_github_dependency_sbom")
    access = _access_state(sbom_evidence)
    if access != "AVAILABLE":
        return _access_result(
            control_id="DEP-001",
            item=sbom_evidence,
            subject=subject,
            reason_prefix="dependency_sbom_visibility",
        )

    sbom = _observation(sbom_evidence).get("sbom")
    if not isinstance(sbom, Mapping):
        return _result(
            "DEP-001",
            "UNKNOWN_ERROR",
            subject,
            [str(sbom_evidence["id"])],
            reason="dependency_sbom_payload_missing",
        )

    packages = int(sbom.get("packages_count") or 0)
    if packages > 0:
        return _result(
            "DEP-001",
            "PASS",
            subject,
            [str(sbom_evidence["id"])],
            reason=f"dependency_sbom_visible:packages={packages}",
        )

    return _result(
        "DEP-001",
        "FINDING",
        subject,
        [str(sbom_evidence["id"])],
        reason="dependency_sbom_empty",
        candidates=["candidate_DEP-001_empty_sbom"],
    )


def _evaluate_dependabot_updates(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    repository = _find(evidence, "ev_github_repository")
    access = _access_state(repository)
    if access != "AVAILABLE":
        return _access_result(
            control_id="DEP-002",
            item=repository,
            subject=subject,
            reason_prefix="dependabot_configuration_visibility",
        )

    security = _observation(repository).get("security_and_analysis")
    status = (
        security.get("dependabot_security_updates")
        if isinstance(security, Mapping)
        else None
    )
    evidence_ids = [str(repository["id"])]
    if status is None:
        return _result(
            "DEP-002",
            "INCONCLUSIVE",
            subject,
            evidence_ids,
            reason="dependabot_security_updates_not_exposed",
        )
    if str(status).lower() != "enabled":
        return _result(
            "DEP-002",
            "FINDING",
            subject,
            evidence_ids,
            reason=f"dependabot_security_updates={status}",
            candidates=["candidate_DEP-002_security_updates_disabled"],
        )
    return _result(
        "DEP-002",
        "PASS",
        subject,
        evidence_ids,
        reason="dependabot_security_updates=enabled",
    )


def _evaluate_dependabot_alerts(
    evidence: Sequence[Mapping[str, Any]],
    subject: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return _evaluate_alert_surface(
        item=_find(evidence, "ev_github_dependabot_alerts"),
        control_id="DEP-003",
        repository_subject=subject,
        reason_prefix="dependabot_alert_visibility",
        empty_alert_reason="dependabot_alerts_visible:no_open_alerts",
        build_finding=_dependabot_alert_finding,
    )


def evaluate_github_security(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    items = list(evidence)
    subject = _repo_subject(items)

    results: list[dict[str, Any]] = [
        _evaluate_code_scanning_coverage(items, subject),
        *_evaluate_code_scanning_alerts(items, subject),
        *_evaluate_secret_scanning(items, subject),
        _evaluate_dependency_sbom(items, subject),
        _evaluate_dependabot_updates(items, subject),
        *_evaluate_dependabot_alerts(items, subject),
    ]
    return results

