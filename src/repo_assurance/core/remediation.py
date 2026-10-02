from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence


_TRACK_ORDER = {
    "CI Stabilization": 10,
    "GitHub Governance": 20,
    "Current Platform Modernization": 30,
    "Repository Hygiene": 40,
}


def _subject_key(finding: Mapping[str, Any]) -> tuple[str, str]:
    subject = finding.get("subject")
    if not isinstance(subject, Mapping):
        return ("unknown", "unknown")
    return (
        str(subject.get("type", "unknown")),
        str(subject.get("identifier", "unknown")),
    )


def _finding_id(finding: Mapping[str, Any]) -> str:
    return str(finding.get("id", "unknown"))


def _step(
    *,
    kind: str,
    action: str,
    finding_ids: Sequence[str],
    blocked_by: Sequence[str] = (),
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": kind,
        "action": action,
        "finding_ids": sorted(set(finding_ids)),
    }
    if blocked_by:
        item["blocked_by"] = sorted(set(blocked_by))
    return item


def build_remediation_tracks(
    findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build deterministic, dependency-aware remediation tracks without applying changes."""
    ordered_findings = sorted(
        findings,
        key=lambda item: (_subject_key(item), str(item.get("type", "")), _finding_id(item)),
    )
    by_subject: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for finding in ordered_findings:
        by_subject[_subject_key(finding)].append(finding)

    track_steps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    track_findings: dict[str, set[str]] = defaultdict(set)

    for subject_key in sorted(by_subject):
        subject_findings = by_subject[subject_key]
        identifier = subject_key[1]
        unreliable = [item for item in subject_findings if item.get("type") == "UNRELIABLE_GATE"]
        enforcement = [item for item in subject_findings if item.get("type") == "ENFORCEMENT_GAP"]
        stale = [item for item in subject_findings if item.get("type") == "STALE_CONTROL"]
        preservation = [item for item in subject_findings if item.get("type") == "PRESERVATION_RISK"]
        cleanup = [item for item in subject_findings if item.get("type") == "CLEANUP_CANDIDATE"]
        deprecation = [item for item in subject_findings if item.get("type") == "DEPRECATION_RISK"]

        if unreliable:
            ids = [_finding_id(item) for item in unreliable]
            track_steps["CI Stabilization"].append(_step(
                kind="STABILIZE_CONTROL",
                action=f"Stabilize {identifier} before relying on it as a gate.",
                finding_ids=ids,
            ))
            track_steps["CI Stabilization"].append(_step(
                kind="VERIFY_STABILITY",
                action=f"Verify repeated healthy executions for {identifier} under equivalent conditions.",
                finding_ids=ids,
            ))
            track_findings["CI Stabilization"].update(ids)

        if stale:
            ids = [_finding_id(item) for item in stale]
            track_steps["CI Stabilization"].append(_step(
                kind="RESTORE_OR_RETIRE_CONTROL",
                action=f"Restore meaningful execution for {identifier} or retire the stale control deliberately.",
                finding_ids=ids,
            ))
            track_findings["CI Stabilization"].update(ids)

        if enforcement:
            ids = [_finding_id(item) for item in enforcement]
            if unreliable:
                blockers = [_finding_id(item) for item in unreliable]
                track_steps["CI Stabilization"].append(_step(
                    kind="ENFORCE_CONTROL",
                    action=f"Enforce {identifier} only after reliability is verified.",
                    finding_ids=ids,
                    blocked_by=blockers,
                ))
                track_findings["CI Stabilization"].update(ids)
            else:
                track_steps["GitHub Governance"].append(_step(
                    kind="ENFORCE_CONTROL",
                    action=f"Review and enforce {identifier} where it is intended to block merges.",
                    finding_ids=ids,
                ))
                track_findings["GitHub Governance"].update(ids)

        if preservation:
            ids = [_finding_id(item) for item in preservation]
            track_steps["Repository Hygiene"].append(_step(
                kind="PRESERVE_WORK",
                action=f"Preserve and review unique work for {identifier} before any cleanup.",
                finding_ids=ids,
            ))
            track_findings["Repository Hygiene"].update(ids)
        elif cleanup:
            ids = [_finding_id(item) for item in cleanup]
            track_steps["Repository Hygiene"].append(_step(
                kind="REVIEW_CLEANUP",
                action=f"Review {identifier} as a cleanup candidate; do not remove it automatically.",
                finding_ids=ids,
            ))
            track_findings["Repository Hygiene"].update(ids)

        if deprecation:
            ids = [_finding_id(item) for item in deprecation]
            track_steps["Current Platform Modernization"].append(_step(
                kind="PLAN_MODERNIZATION",
                action=f"Migrate {identifier} before the documented lifecycle deadline.",
                finding_ids=ids,
            ))
            track_findings["Current Platform Modernization"].update(ids)

    tracks: list[dict[str, Any]] = []
    for title in sorted(track_steps, key=lambda item: (_TRACK_ORDER.get(item, 999), item)):
        tracks.append({
            "id": "track_" + title.lower().replace(" ", "_"),
            "title": title,
            "finding_ids": sorted(track_findings[title]),
            "steps": track_steps[title],
        })
    return tracks
