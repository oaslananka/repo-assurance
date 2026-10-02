from __future__ import annotations

from typing import Any, Mapping


_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _finding_sort_key(item: Mapping[str, Any]) -> tuple[int, int, str]:
    return (
        _PRIORITY_ORDER.get(str(item.get("priority")), 99),
        _SEVERITY_ORDER.get(str(item.get("severity")), 99),
        str(item.get("id", "")),
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    audit = report.get("audit", {})
    repository = report.get("repository", {})
    snapshot = report.get("snapshot", {})
    lines = [
        "# Repository Assurance Audit",
        "",
        f"- Repository: `{repository.get('full_name', 'unknown')}`",
        f"- Target branch: `{snapshot.get('target_branch', 'unknown')}`",
        f"- Target SHA: `{snapshot.get('target_commit_sha', 'unknown')}`",
        f"- Mode: `{audit.get('mode', 'unknown')}`",
        f"- Audit completed: `{audit.get('completed_at', 'unknown')}`",
        f"- Baseline as of: `{audit.get('baseline_as_of', 'unknown')}`",
        "",
        "## Assurance Coverage",
        "",
        "| Domain | State |",
        "| --- | --- |",
    ]
    for domain, state in sorted(dict(report.get("coverage", {})).items()):
        lines.append(f"| {domain} | {state} |")

    lines.extend(["", "## Priority Findings", ""])
    findings = sorted(report.get("findings", []), key=_finding_sort_key)
    if not findings:
        lines.append("No material canonical findings were produced within the verified audit scope.")
    for finding in findings:
        subject = finding.get("subject", {})
        lines.extend([
            f"### {finding.get('priority')} · {finding.get('title')}",
            "",
            f"- ID: `{finding.get('id')}`",
            f"- Severity: `{finding.get('severity')}`",
            f"- Confidence: `{finding.get('confidence')}`",
            f"- Subject: `{subject.get('identifier', 'unknown')}`",
            f"- Why it matters: {finding.get('impact', {}).get('summary', '')}",
            f"- Evidence: {', '.join('`' + str(item) + '`' for item in finding.get('evidence_ids', [])) or 'none'}",
            f"- Recommended action: {finding.get('remediation', {}).get('summary', '')}",
            "",
        ])

    lines.extend(["## Remediation Tracks", ""])
    tracks = report.get("remediation_tracks", [])
    if not tracks:
        lines.append("No remediation tracks were generated.")
    for track in tracks:
        lines.append(f"### {track.get('title', 'Untitled track')}")
        lines.append("")
        for index, step in enumerate(track.get("steps", []), start=1):
            blocked = step.get("blocked_by", [])
            suffix = f" (blocked by: {', '.join(blocked)})" if blocked else ""
            lines.append(f"{index}. {step.get('action', '')}{suffix}")
        lines.append("")

    lines.extend(["## Blind Spots", ""])
    blind_spots = report.get("blind_spots", [])
    if not blind_spots:
        lines.append("No explicit blind spots were recorded for the planned controls.")
    for blind_spot in blind_spots:
        lines.append(f"- **{blind_spot.get('domain', 'unknown')}**: {blind_spot.get('summary', '')}")

    lines.extend([
        "",
        "## Technical Appendix",
        "",
        f"- Planned controls: {report.get('plan_summary', {}).get('catalog_controls', 0)}",
        f"- Applicable controls: {report.get('plan_summary', {}).get('applicable', 0)}",
        f"- Control results: {len(report.get('control_results', []))}",
        f"- Canonical findings: {len(findings)}",
        "",
    ])
    return "\n".join(lines)
