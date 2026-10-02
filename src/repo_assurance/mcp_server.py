from __future__ import annotations

from typing import Any, Literal, Mapping, Sequence

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from repo_assurance.plugin.api import (
    audit_repository as _audit_repository,
    discover_repository as _discover_repository,
    plan_repository_audit as _plan_repository_audit,
    render_audit_report as _render_audit_report,
)

mcp = MCPServer("Repo Assurance")


@mcp.tool(
    title="Discover repository",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
def discover_repository(repo_path: str, target: str | None = None) -> dict[str, Any]:
    """Discover a local Git repository's immutable snapshot, profile, and audit capabilities."""
    return _discover_repository(repo_path, target)


@mcp.tool(
    title="Plan repository audit",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
def plan_repository_audit(
    repo_path: str,
    target: str | None = None,
    mode: Literal["quick", "standard", "deep"] = "standard",
) -> dict[str, Any]:
    """Build the applicable control plan for a repository without running the audit."""
    return _plan_repository_audit(repo_path, target=target, mode=mode)


@mcp.tool(
    title="Audit repository",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
)
def audit_repository(
    repo_path: str,
    target: str | None = None,
    mode: Literal["quick", "standard", "deep"] = "standard",
    offline: bool = False,
    history_days: int | None = None,
    max_runs: int | None = None,
    baseline_evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Run a read-only audit. Current-sensitive evidence may be supplied from authoritative sources."""
    return _audit_repository(
        repo_path,
        target=target,
        mode=mode,
        offline=offline,
        history_days=history_days,
        max_runs=max_runs,
        baseline_evidence=baseline_evidence,
    )


@mcp.tool(
    title="Render audit report",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
def render_audit_report(
    report: Mapping[str, Any],
    format: Literal["json", "markdown"] = "markdown",
) -> str:
    """Render a canonical Repo Assurance report without changing its findings or policy."""
    return _render_audit_report(report, format=format)


if __name__ == "__main__":
    mcp.run()
