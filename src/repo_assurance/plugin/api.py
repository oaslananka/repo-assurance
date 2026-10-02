from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Mapping

from repo_assurance.cli import _audit, _build_plan, _discover
from repo_assurance.core.schema import validate_document
from repo_assurance.renderers.json_report import render_json
from repo_assurance.renderers.markdown_report import render_markdown

AuditMode = Literal["quick", "standard", "deep"]
RenderFormat = Literal["json", "markdown"]


def _repo_path(repo_path: str) -> Path:
    path = Path(repo_path).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"repository path is not a directory: {path}")
    return path


def discover_repository(repo_path: str, target: str | None = None) -> dict[str, Any]:
    """Discover repository identity, immutable snapshot, profile, and capabilities."""
    discovery = _discover(_repo_path(repo_path), target)
    return {
        "repository": discovery["repository"],
        "snapshot": discovery["snapshot"],
        "profile": discovery["profile"],
        "capabilities": discovery["capabilities"],
    }


def plan_repository_audit(
    repo_path: str,
    target: str | None = None,
    mode: AuditMode = "standard",
) -> dict[str, Any]:
    """Build a repository-specific audit plan without running the audit."""
    plan, _ = _build_plan(_repo_path(repo_path), target=target, mode=mode)
    return plan


def audit_repository(
    repo_path: str,
    target: str | None = None,
    mode: AuditMode = "standard",
    offline: bool = False,
    history_days: int | None = None,
    max_runs: int | None = None,
) -> dict[str, Any]:
    """Run the canonical read-only audit and return plan/report metadata without raw evidence."""
    plan, report, evidence = _audit(
        _repo_path(repo_path),
        target=target,
        mode=mode,
        history_days=history_days,
        max_runs=max_runs,
        offline=offline,
        no_current_baseline=offline,
    )
    return {
        "plan": plan,
        "report": report,
        "evidence_count": len(evidence),
    }


def render_audit_report(
    report: Mapping[str, Any],
    format: RenderFormat = "markdown",
) -> str:
    """Render an already-canonical audit report without recomputing findings or policy."""
    validate_document("audit-report.v1", report)
    if format == "json":
        return render_json(report)
    return render_markdown(report)
