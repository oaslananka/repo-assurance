from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


class CorrelationError(ValueError):
    """Raised when a candidate finding cannot be grounded in canonical evidence."""


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    control_id: str
    finding_type: str
    severity: str
    confidence: str
    root_discriminator: str


_RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        "CORR-CHRONIC-FAILURE",
        "CI-OPS-003",
        "CHRONIC_FAILURE",
        "MEDIUM",
        "HIGH",
        "chronic-workflow-failure",
    ),
    CorrelationRule(
        "CORR-FLAKY-JOB",
        "CI-OPS-005",
        "FLAKY_JOB",
        "MEDIUM",
        "HIGH",
        "rerun-recovery-flakiness",
    ),
    CorrelationRule(
        "CORR-STALE-REQUIRED-CHECK",
        "GH-GOV-003",
        "STALE_REQUIRED_CHECK",
        "MEDIUM",
        "CONFIRMED",
        "stale-required-check",
    ),
    CorrelationRule(
        "CORR-RUNNER-DEPRECATION",
        "CI-STATIC-008",
        "DEPRECATION_RISK",
        "MEDIUM",
        "HIGH",
        "runner-lifecycle-risk",
    ),
    CorrelationRule(
        "CORR-UNRELIABLE-GATE",
        "CI-OPS-006",
        "UNRELIABLE_GATE",
        "HIGH",
        "CONFIRMED",
        "required-unreliable-gate",
    ),
    CorrelationRule(
        "CORR-ENFORCEMENT-GAP",
        "CI-OPS-007",
        "ENFORCEMENT_GAP",
        "MEDIUM",
        "HIGH",
        "healthy-expected-gate-not-required",
    ),
    CorrelationRule(
        "CORR-STALE-CONTROL",
        "CI-OPS-008",
        "STALE_CONTROL",
        "MEDIUM",
        "HIGH",
        "expected-workflow-not-operating",
    ),
    CorrelationRule(
        "CORR-CLEANUP-CANDIDATE",
        "HYGIENE-001",
        "CLEANUP_CANDIDATE",
        "INFO",
        "HIGH",
        "integrated-stale-branch",
    ),
    CorrelationRule(
        "CORR-LOCAL-ONLY-WORK",
        "HYGIENE-003",
        "PRESERVATION_RISK",
        "HIGH",
        "HIGH",
        "local-only-unique-work",
    ),
    CorrelationRule(
        "CORR-REMOTE-DELETED-WORK",
        "HYGIENE-004",
        "PRESERVATION_RISK",
        "HIGH",
        "CONFIRMED",
        "remote-deleted-local-unique-work",
    ),
    CorrelationRule(
        "CORR-DEPENDENCY-VULNERABILITY",
        "DEP-003",
        "DEPENDENCY_VULNERABILITY",
        "MEDIUM",
        "HIGH",
        "dependency-advisory",
    ),
    CorrelationRule(
        "CORR-DIRTY-WORKTREE",
        "HYGIENE-005",
        "PRESERVATION_RISK",
        "HIGH",
        "CONFIRMED",
        "dirty-worktree",
    ),
    CorrelationRule(
        "CORR-DETACHED-UNIQUE-WORK",
        "HYGIENE-008",
        "PRESERVATION_RISK",
        "HIGH",
        "CONFIRMED",
        "detached-unique-work",
    ),
)


def _subject_identifier(result: Mapping[str, Any]) -> str:
    subject = result.get("subject")
    if isinstance(subject, Mapping):
        return str(subject.get("identifier", "unknown"))
    return "unknown"


def _candidate_id(rule: CorrelationRule, result: Mapping[str, Any]) -> str:
    identifier = _subject_identifier(result)
    safe = "".join(ch if ch.isalnum() else "_" for ch in identifier).strip("_") or "unknown"
    return f"candidate_{rule.rule_id}_{safe}"


def _ground_result(
    result: Mapping[str, Any],
    *,
    control_id: str,
    evidence_ids: set[str],
) -> tuple[dict[str, Any], list[str]]:
    referenced = [str(item) for item in result.get("evidence_ids", [])]
    missing = sorted(set(referenced) - evidence_ids)
    if missing:
        raise CorrelationError(
            f"missing evidence for {control_id}: {','.join(missing)}"
        )
    if not referenced:
        raise CorrelationError(
            f"missing evidence for {control_id}: no evidence ids"
        )

    subject = result.get("subject")
    if not isinstance(subject, Mapping):
        raise CorrelationError(
            f"invalid subject for {control_id}"
        )
    return dict(subject), sorted(set(referenced))


def _fallback_candidate_ids(
    result: Mapping[str, Any],
    *,
    control_id: str,
) -> list[str]:
    supplied = sorted({
        str(item)
        for item in result.get("candidate_finding_ids", [])
        if str(item)
    })
    if supplied:
        return supplied

    identifier = _subject_identifier(result)
    safe_control = "".join(
        ch if ch.isalnum() else "_" for ch in control_id
    ).strip("_") or "unknown_control"
    safe_subject = "".join(
        ch if ch.isalnum() else "_" for ch in identifier
    ).strip("_") or "unknown"
    return [f"candidate_UNMAPPED_{safe_control}_{safe_subject}"]


def correlate(
    *,
    control_results: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Convert grounded control findings into deterministic candidate findings."""
    evidence_ids = {
        str(item.get("id"))
        for item in evidence
        if item.get("id") is not None
    }
    by_control: dict[str, list[Mapping[str, Any]]] = {}
    for item in control_results:
        by_control.setdefault(str(item.get("control_id")), []).append(item)

    candidates: list[dict[str, Any]] = []
    materialized_result_ids: set[int] = set()

    for rule in _RULES:
        matches = sorted(
            by_control.get(rule.control_id, []),
            key=_subject_identifier,
        )
        for result in matches:
            if result.get("state") != "FINDING":
                continue

            subject, referenced = _ground_result(
                result,
                control_id=rule.control_id,
                evidence_ids=evidence_ids,
            )

            candidate = {
                "schema_version": "candidate-finding/v1",
                "candidate_id": _candidate_id(rule, result),
                "control_id": rule.control_id,
                "subject": subject,
                "type": rule.finding_type,
                "evidence_ids": referenced,
                "proposed_severity": rule.severity,
                "proposed_confidence": rule.confidence,
                "root_discriminator": rule.root_discriminator,
            }
            validate_document("candidate-finding.v1", candidate)
            candidates.append(candidate)
            materialized_result_ids.add(id(result))

    # Provider dependency advisories share the same canonical root identity as
    # GitHub dependency advisories so the same upstream advisory can dedupe across
    # providers.
    provider_dependency_results = sorted(
        (
            result
            for result in by_control.get("PROV-003", [])
            if result.get("state") == "FINDING"
            and id(result) not in materialized_result_ids
            and isinstance(result.get("subject"), Mapping)
            and result["subject"].get("type") == "dependency"
        ),
        key=_subject_identifier,
    )
    for result in provider_dependency_results:
        subject, referenced = _ground_result(
            result,
            control_id="PROV-003",
            evidence_ids=evidence_ids,
        )
        for candidate_id in _fallback_candidate_ids(
            result,
            control_id="PROV-003",
        ):
            candidate = {
                "schema_version": "candidate-finding/v1",
                "candidate_id": candidate_id,
                "control_id": "PROV-003",
                "subject": subject,
                "type": "DEPENDENCY_VULNERABILITY",
                "evidence_ids": referenced,
                "proposed_severity": "MEDIUM",
                "proposed_confidence": "HIGH",
                "root_discriminator": "dependency-advisory",
            }
            validate_document("candidate-finding.v1", candidate)
            candidates.append(candidate)
        materialized_result_ids.add(id(result))

    # Fail-safe materialization contract: a grounded material negative result must
    # never disappear merely because a specialized correlation rule has not yet
    # been registered. Specialized rules above remain authoritative when present.
    fallback_results = sorted(
        (
            result
            for result in control_results
            if result.get("state") == "FINDING"
            and id(result) not in materialized_result_ids
        ),
        key=lambda item: (
            str(item.get("control_id", "")),
            _subject_identifier(item),
        ),
    )
    for result in fallback_results:
        control_id = str(result.get("control_id", "UNKNOWN"))
        subject, referenced = _ground_result(
            result,
            control_id=control_id,
            evidence_ids=evidence_ids,
        )
        for candidate_id in _fallback_candidate_ids(
            result,
            control_id=control_id,
        ):
            candidate = {
                "schema_version": "candidate-finding/v1",
                "candidate_id": candidate_id,
                "control_id": control_id,
                "subject": subject,
                "type": "CONTROL_FINDING",
                "evidence_ids": referenced,
                "proposed_severity": "MEDIUM",
                "proposed_confidence": "HIGH",
                "root_discriminator": f"control-finding:{control_id}",
            }
            validate_document("candidate-finding.v1", candidate)
            candidates.append(candidate)

    return candidates
