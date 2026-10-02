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
    for rule in _RULES:
        matches = sorted(
            by_control.get(rule.control_id, []),
            key=_subject_identifier,
        )
        for result in matches:
            if result.get("state") != "FINDING":
                continue

            referenced = [str(item) for item in result.get("evidence_ids", [])]
            missing = sorted(set(referenced) - evidence_ids)
            if missing:
                raise CorrelationError(
                    f"missing evidence for {rule.control_id}: {','.join(missing)}"
                )
            if not referenced:
                raise CorrelationError(
                    f"missing evidence for {rule.control_id}: no evidence ids"
                )

            subject = result.get("subject")
            if not isinstance(subject, Mapping):
                raise CorrelationError(
                    f"invalid subject for {rule.control_id}"
                )

            candidate = {
                "schema_version": "candidate-finding/v1",
                "candidate_id": _candidate_id(rule, result),
                "control_id": rule.control_id,
                "subject": dict(subject),
                "type": rule.finding_type,
                "evidence_ids": sorted(set(referenced)),
                "proposed_severity": rule.severity,
                "proposed_confidence": rule.confidence,
                "root_discriminator": rule.root_discriminator,
            }
            validate_document("candidate-finding.v1", candidate)
            candidates.append(candidate)

    return candidates
