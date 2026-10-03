from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence

from repo_assurance.core.fingerprints import build_finding_fingerprint


_FAMILY_BY_TYPE = {
    "UNRELIABLE_GATE": "CICD",
    "STALE_CONTROL": "CICD",
    "ENFORCEMENT_GAP": "GOVERNANCE",
    "PRESERVATION_RISK": "HYGIENE",
    "CLEANUP_CANDIDATE": "HYGIENE",
}


def _normalized_subject(subject: Mapping[str, Any]) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    subject_type = str(subject.get("type", "unknown")).strip().lower()
    identifier = str(subject.get("identifier", "unknown")).strip().replace("\\", "/")
    qualifiers = subject.get("qualifiers")
    if isinstance(qualifiers, Mapping):
        qualifier_items = tuple(sorted((str(key), repr(value)) for key, value in qualifiers.items()))
    else:
        qualifier_items = ()
    return subject_type, identifier, qualifier_items


def _group_key(candidate: Mapping[str, Any]) -> tuple[object, ...]:
    subject = candidate.get("subject")
    if not isinstance(subject, Mapping):
        subject = {"type": "unknown", "identifier": "unknown"}
    finding_type = str(candidate.get("type", "UNKNOWN"))
    normalized = _normalized_subject(subject)
    if finding_type == "DEPENDENCY_VULNERABILITY":
        normalized = (normalized[0], normalized[1], ())
    return (
        finding_type,
        str(candidate.get("root_discriminator", "unknown")),
        *normalized,
    )


def deduplicate_candidates(
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Group semantically equivalent candidates while preserving all evidence sources."""
    grouped: dict[tuple[object, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        grouped[_group_key(candidate)].append(candidate)

    output: list[dict[str, Any]] = []
    for key in sorted(grouped, key=repr):
        items = sorted(grouped[key], key=lambda item: str(item.get("candidate_id", "")))
        first = items[0]
        subject = dict(first.get("subject", {}))
        finding_type = str(first.get("type", "UNKNOWN"))
        if finding_type == "DEPENDENCY_VULNERABILITY":
            subject = {
                "type": str(subject.get("type", "dependency")),
                "identifier": str(subject.get("identifier", "unknown")),
            }
        root = str(first.get("root_discriminator", "unknown"))
        family = _FAMILY_BY_TYPE.get(finding_type, finding_type)
        fingerprint = build_finding_fingerprint(
            control_family=family,
            subject=subject,
            root_discriminator=root,
        )
        output.append(
            {
                "fingerprint": fingerprint,
                "type": finding_type,
                "subject": subject,
                "root_discriminator": root,
                "candidate_ids": sorted({str(item.get("candidate_id")) for item in items}),
                "control_ids": sorted({str(item.get("control_id")) for item in items}),
                "evidence_ids": sorted({
                    str(evidence_id)
                    for item in items
                    for evidence_id in item.get("evidence_ids", [])
                }),
                "proposed_severities": sorted({str(item.get("proposed_severity")) for item in items}),
                "proposed_confidences": sorted({str(item.get("proposed_confidence")) for item in items}),
            }
        )
    return output
