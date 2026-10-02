from __future__ import annotations

from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


_TEMPLATES: dict[str, dict[str, str]] = {
    "UNRELIABLE_GATE": {
        "prefix": "CICD-UNRELIABLE",
        "title": "Required CI gate is unreliable",
        "domain": "cicd",
        "output_class": "FINDING",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "priority": "P1",
        "observed": "Observed execution evidence shows the required CI gate is not reliably operating within the audited window.",
        "expected": "A required merge gate should provide a reliable and repeatable signal.",
        "impact": "An unreliable required gate can block valid work or train maintainers to ignore red CI.",
        "root_state": "SUSPECTED",
        "root_summary": "The effective CI control is unreliable; the specific failure mechanism requires the linked evidence for diagnosis.",
        "remediation": "Stabilize the failing control before relying on it as a required merge gate.",
        "effort": "M",
        "verification": "Observe repeated successful executions under equivalent conditions before enforcing the gate.",
    },
    "ENFORCEMENT_GAP": {
        "prefix": "GOV-ENFORCEMENT",
        "title": "Expected assurance control is not enforced",
        "domain": "github_governance",
        "output_class": "FINDING",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "priority": "P2",
        "observed": "The control is operating but is not enforced as an expected merge gate.",
        "expected": "Controls intended to block unsafe or unverified changes should be enforced at merge time.",
        "impact": "Changes can merge without satisfying an assurance control that is expected to be blocking.",
        "root_state": "CONFIRMED",
        "root_summary": "The observed control state and merge enforcement state are inconsistent.",
        "remediation": "Review policy intent and make the control required only after its reliability is verified.",
        "effort": "S",
        "verification": "Confirm the effective ruleset requires the intended check and a compliant pull request cannot bypass it.",
    },
    "STALE_CONTROL": {
        "prefix": "CICD-STALE",
        "title": "Configured CI control is stale or inactive",
        "domain": "cicd",
        "output_class": "FINDING",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "priority": "P2",
        "observed": "A configured workflow or control did not produce the expected meaningful execution evidence.",
        "expected": "An active assurance control should execute when its documented trigger conditions occur.",
        "impact": "A stale control creates false confidence because configuration exists without effective execution.",
        "root_state": "SUSPECTED",
        "root_summary": "The configured control is not effectively operating in the observed audit window.",
        "remediation": "Restore meaningful execution or retire the stale control deliberately.",
        "effort": "M",
        "verification": "Trigger the intended conditions and verify the control executes successfully.",
    },
    "PRESERVATION_RISK": {
        "prefix": "HYGIENE-PRESERVE",
        "title": "Repository work may exist only in a local or fragile reference",
        "domain": "repository_hygiene",
        "output_class": "FINDING",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "priority": "P1",
        "observed": "Unique or dirty work was observed in a local branch, detached commit, or worktree preservation surface.",
        "expected": "Valuable work should have an intentional durable reference before cleanup is considered.",
        "impact": "Cleanup can permanently discard work that is not preserved elsewhere.",
        "root_state": "CONFIRMED",
        "root_summary": "The audited Git state contains work that must be preserved or explicitly discarded before cleanup.",
        "remediation": "Preserve and review the work before deleting branches, worktrees, stashes, or detached commits.",
        "effort": "S",
        "verification": "Verify the work is durably referenced or intentionally discarded before any cleanup action.",
    },
    "CLEANUP_CANDIDATE": {
        "prefix": "HYGIENE-CLEANUP",
        "title": "Integrated repository reference is a cleanup candidate",
        "domain": "repository_hygiene",
        "output_class": "OBSERVATION",
        "severity": "INFO",
        "confidence": "HIGH",
        "priority": "P4",
        "observed": "The reference appears stale, integrated, and free of detected unique work or dirty attached worktrees.",
        "expected": "Obsolete integrated references can be removed after preservation checks complete.",
        "impact": "Leaving obsolete references can increase repository clutter and make active work harder to distinguish.",
        "root_state": "CONFIRMED",
        "root_summary": "Strong integration evidence exists and no preservation signal was observed for this reference.",
        "remediation": "Review the reference as a cleanup candidate; do not remove it automatically.",
        "effort": "XS",
        "verification": "Reconfirm no unique or dirty work exists immediately before cleanup.",
    },
    "DEPRECATION_RISK": {
        "prefix": "CURRENT-DEPRECATION",
        "title": "Current platform lifecycle creates a deprecation risk",
        "domain": "current_platform",
        "output_class": "FINDING",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "priority": "P2",
        "observed": "Authoritative current-baseline evidence indicates a configured platform component is retiring, deprecated, unsupported, or removed.",
        "expected": "Active repository automation should use supported platform components.",
        "impact": "The affected workflow or integration can fail when the documented lifecycle change takes effect.",
        "root_state": "CONFIRMED",
        "root_summary": "The configured component conflicts with current authoritative lifecycle evidence.",
        "remediation": "Migrate to a supported replacement before the documented lifecycle deadline.",
        "effort": "S",
        "verification": "Confirm the replacement is supported by current authoritative documentation and the workflow remains healthy.",
    },
}


def _fallback_template(group: Mapping[str, Any]) -> dict[str, str]:
    severity_candidates = [str(item) for item in group.get("proposed_severities", [])]
    confidence_candidates = [str(item) for item in group.get("proposed_confidences", [])]
    return {
        "prefix": "ASSURANCE-FINDING",
        "title": "Repository assurance finding",
        "domain": "repository",
        "output_class": "FINDING",
        "severity": severity_candidates[0] if len(set(severity_candidates)) == 1 and severity_candidates else "MEDIUM",
        "confidence": confidence_candidates[0] if len(set(confidence_candidates)) == 1 and confidence_candidates else "MEDIUM",
        "priority": "P3",
        "observed": "Canonical evidence produced an assurance finding for the audited subject.",
        "expected": "The relevant assurance control should satisfy the repository's intended policy.",
        "impact": "The observed state may reduce repository assurance until reviewed.",
        "root_state": "UNKNOWN",
        "root_summary": "The canonical evidence identifies the condition but not a confirmed root cause.",
        "remediation": "Review the linked evidence and remediate the underlying condition.",
        "effort": "M",
        "verification": "Repeat the audit and confirm the finding no longer reproduces.",
    }


def materialize_findings(
    groups: Sequence[Mapping[str, Any]],
    *,
    baseline_as_of: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for group in sorted(groups, key=lambda item: str(item.get("fingerprint", ""))):
        finding_type = str(group.get("type", "UNKNOWN"))
        template = _TEMPLATES.get(finding_type) or _fallback_template(group)
        fingerprint = str(group["fingerprint"])
        short_hash = fingerprint.removeprefix("sha256:")[:8]
        finding = {
            "schema_version": "finding/v1",
            "id": f"{template['prefix']}-{short_hash}",
            "fingerprint": fingerprint,
            "control_ids": sorted({str(item) for item in group.get("control_ids", [])}),
            "title": template["title"],
            "domain": template["domain"],
            "type": finding_type,
            "output_class": template["output_class"],
            "severity": template["severity"],
            "confidence": template["confidence"],
            "priority": template["priority"],
            "lifecycle": "OPEN",
            "subject": dict(group.get("subject", {})),
            "observed": {"summary": template["observed"]},
            "expected": {"summary": template["expected"]},
            "impact": {"summary": template["impact"]},
            "evidence_ids": sorted({str(item) for item in group.get("evidence_ids", [])}),
            "root_cause": {
                "state": template["root_state"],
                "summary": template["root_summary"],
            },
            "remediation": {
                "summary": template["remediation"],
                "effort": template["effort"],
            },
            "verification": {"summary": template["verification"]},
            "baseline_as_of": baseline_as_of,
            "relationships": {
                "caused_by": [],
                "related_to": [],
                "duplicates": [],
                "blocked_by": [],
                "blocks": [],
            },
        }
        validate_document("finding.v1", finding)
        findings.append(finding)
    return findings
