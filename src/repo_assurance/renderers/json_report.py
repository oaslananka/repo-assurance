from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


def build_audit_report(
    *,
    audit_id: str,
    mode: str,
    started_at: str,
    completed_at: str,
    baseline_as_of: str,
    repository: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    profile: Mapping[str, Any],
    audit_plan: Mapping[str, Any],
    coverage: Mapping[str, str],
    control_results: Sequence[Mapping[str, Any]],
    providers: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    blind_spots: Sequence[Mapping[str, Any]],
    remediation_tracks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    for finding in findings:
        validate_document("finding.v1", finding)

    planned_controls = [item for item in audit_plan.get("controls", []) if isinstance(item, Mapping)]
    applicable = sum(1 for item in planned_controls if item.get("applicable") is True)
    report = {
        "schema_version": "audit-report/v1",
        "audit": {
            "id": audit_id,
            "mode": mode,
            "started_at": started_at,
            "completed_at": completed_at,
            "baseline_as_of": baseline_as_of,
        },
        "repository": dict(repository),
        "snapshot": dict(snapshot),
        "profile": dict(profile),
        "plan_summary": {
            "catalog_controls": len(planned_controls),
            "applicable": applicable,
            "not_applicable": len(planned_controls) - applicable,
        },
        "coverage": dict(sorted(coverage.items())),
        "control_results": [dict(item) for item in control_results],
        "providers": [dict(item) for item in providers],
        "findings": [dict(item) for item in findings],
        "observations": [dict(item) for item in observations],
        "blind_spots": [dict(item) for item in blind_spots],
        "remediation_tracks": [dict(item) for item in remediation_tracks],
    }
    validate_document("audit-report.v1", report)
    return report


def render_json(report: Mapping[str, Any]) -> str:
    validate_document("audit-report.v1", report)
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
