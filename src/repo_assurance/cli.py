from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from repo_assurance.collectors.actionlint import collect_actionlint_evidence
from repo_assurance.collectors.baseline import (
    load_baseline_evidence,
    match_baseline_request,
)
from repo_assurance.collectors.filesystem import (
    collect_repository_profile_evidence,
    collect_workflow_sources,
)
from repo_assurance.collectors.git import (
    collect_branches,
    collect_repository_identity,
    collect_snapshot,
    collect_stashes,
    collect_worktrees,
)
from repo_assurance.collectors.github import (
    collect_commit_checks,
    collect_default_branch_state,
    collect_repository_state,
    collect_rulesets,
)
from repo_assurance.collectors.github_actions import (
    collect_workflow_history,
    collect_workflows,
)
from repo_assurance.collectors.github_security import (
    collect_code_scanning_alerts,
    collect_code_scanning_analyses,
    collect_dependency_sbom,
    collect_dependabot_alerts,
    collect_secret_scanning_alerts,
)
from repo_assurance.collectors.providers import (
    collect_provider_discovery,
    collect_provider_states,
    provider_summaries,
)
from repo_assurance.core.catalog import load_catalog, validate_catalog_document
from repo_assurance.core.completeness import compute_domain_coverage
from repo_assurance.core.correlation import correlate
from repo_assurance.core.dedupe import deduplicate_candidates
from repo_assurance.core.findings import materialize_findings
from repo_assurance.core.gates import (
    build_required_gate_mapping_evidence,
    required_check_names,
    required_check_requirements,
)
from repo_assurance.core.planner import RepositoryCapabilities, build_audit_plan
from repo_assurance.core.remediation import build_remediation_tracks
from repo_assurance.core.schema import validate_document
from repo_assurance.evaluators.cicd_operational import evaluate_ci_operational
from repo_assurance.evaluators.cicd_static import (
    build_runner_baseline_requests,
    evaluate_ci_static,
)
from repo_assurance.evaluators.governance import evaluate_governance
from repo_assurance.evaluators.github_security import evaluate_github_security
from repo_assurance.evaluators.hygiene import evaluate_hygiene
from repo_assurance.evaluators.providers import evaluate_providers
from repo_assurance.evaluators.repository import (
    discover_repository_profile,
    discover_repository_profile_at_commit,
    evaluate_repository_profile,
)
from repo_assurance.evaluators.snapshot import evaluate_snapshot
from repo_assurance.renderers.json_report import build_audit_report, render_json
from repo_assurance.renderers.markdown_report import render_markdown
from repo_assurance.security.redaction import assert_no_secret_values


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity_metadata(identity_evidence: Sequence[Mapping[str, Any]], repo: Path) -> dict[str, str]:
    if identity_evidence:
        observation = identity_evidence[0].get("observation")
        if isinstance(observation, Mapping):
            full_name = observation.get("full_name")
            owner = observation.get("owner")
            name = observation.get("name")
            if full_name and owner and name:
                return {
                    "owner": str(owner),
                    "name": str(name),
                    "full_name": str(full_name),
                }
    return {
        "owner": "local",
        "name": repo.name,
        "full_name": f"local/{repo.name}",
    }


def _snapshot_metadata(snapshot_evidence: Sequence[Mapping[str, Any]], target_ref: str) -> dict[str, str]:
    for item in snapshot_evidence:
        if item.get("id") != "ev_git_snapshot":
            continue
        observation = item.get("observation")
        if isinstance(observation, Mapping):
            return {
                "target_branch": str(observation.get("target_ref") or target_ref),
                "target_commit_sha": str(observation["target_commit_sha"]),
            }
    raise RuntimeError("immutable snapshot evidence was not collected")


def _capabilities(
    *,
    repository: Mapping[str, str],
    profile: Mapping[str, Any],
) -> RepositoryCapabilities:
    has_github = repository.get("owner") != "local"
    has_actions = bool(profile.get("github_actions"))
    return RepositoryCapabilities(
        {
            "filesystem": True,
            "local_git": True,
            "local_worktrees": True,
            "github": has_github,
            "rulesets": has_github,
            "github_actions": has_actions,
            "workflow_history": bool(has_github and has_actions),
        }
    )


def _discover(repo: Path, target: str | None) -> dict[str, Any]:
    identity = collect_repository_identity(repo)
    snapshot_evidence = collect_snapshot(repo, target)
    snapshot_observation = next(
        item["observation"]
        for item in snapshot_evidence
        if item["id"] == "ev_git_snapshot"
    )
    target_ref = str(snapshot_observation["target_ref"])
    repository = _identity_metadata(identity, repo)
    snapshot = _snapshot_metadata(snapshot_evidence, target_ref)
    profile = discover_repository_profile_at_commit(repo, snapshot["target_commit_sha"])
    return {
        "repository": repository,
        "snapshot": snapshot,
        "profile": profile,
        "capabilities": dict(_capabilities(repository=repository, profile=profile).values),
        "identity_evidence": identity,
        "snapshot_evidence": snapshot_evidence,
    }


def _build_plan(repo: Path, *, target: str | None, mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    discovery = _discover(repo, target)
    repository_for_plan = {
        **discovery["repository"],
        "repository_type": discovery["profile"].get("repository_type", "unknown"),
    }
    plan = build_audit_plan(
        catalog=load_catalog(),
        capabilities=RepositoryCapabilities(discovery["capabilities"]),
        repository=repository_for_plan,
        snapshot=discovery["snapshot"],
        mode=mode,
    )
    return plan, discovery


def _governance_evidence(repository: str, branch: str, sha: str) -> list[dict[str, Any]]:
    repository_state = collect_repository_state(repository, sha)
    default_branch: str | None = None
    if repository_state:
        observation = repository_state[0].get("observation")
        if (
            isinstance(observation, Mapping)
            and observation.get("access_state") == "AVAILABLE"
            and observation.get("default_branch")
        ):
            default_branch = str(observation["default_branch"])

    branch_state = (
        collect_default_branch_state(repository, default_branch, sha)
        if default_branch
        else []
    )
    return [
        *repository_state,
        *collect_rulesets(repository, sha),
        *branch_state,
        *collect_commit_checks(repository, sha),
    ]


def _github_security_evidence(
    repository: str,
    sha: str,
) -> list[dict[str, Any]]:
    return [
        *collect_code_scanning_analyses(repository, sha),
        *collect_code_scanning_alerts(repository, sha),
        *collect_secret_scanning_alerts(repository, sha),
        *collect_dependency_sbom(repository, sha),
        *collect_dependabot_alerts(repository, sha),
    ]


def _actions_history_evidence(
    *,
    repository: str,
    sha: str,
    max_days: int,
    max_runs: int,
) -> tuple[list[dict[str, Any]], set[str]]:
    workflow_inventory = collect_workflows(repository, sha)
    if not workflow_inventory:
        return [], set()
    observation = workflow_inventory[0].get("observation")
    if not isinstance(observation, Mapping):
        return [workflow_inventory[0]], set()
    if observation.get("access_state") != "AVAILABLE":
        # The operational evaluator understands access-state failures and will
        # mark every operational control unavailable instead of treating an
        # empty workflow list as healthy history.
        return [workflow_inventory[0]], set()

    workflows = observation.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        return [], set()

    history: list[dict[str, Any]] = []
    workflow_names: set[str] = set()
    for workflow in workflows:
        if not isinstance(workflow, Mapping) or workflow.get("id") is None:
            continue
        workflow_id = str(workflow["id"])
        if workflow.get("name"):
            workflow_names.add(str(workflow["name"]))
        collected = collect_workflow_history(
            repository=repository,
            workflow_id=workflow_id,
            target_commit_sha=sha,
            max_days=max_days,
            max_runs=max_runs,
        )
        for item in collected:
            item = dict(item)
            item["subject"] = {
                "type": "github_workflow",
                "identifier": str(workflow.get("path") or workflow_id),
                **({"display_name": str(workflow["name"])} if workflow.get("name") else {}),
            }
            item["observation"] = dict(item.get("observation", {}))
            item["observation"]["workflow_id"] = workflow_id
            item["observation"]["workflow_name"] = workflow.get("name")
            item["observation"]["expected_execution"] = workflow.get("state") == "active"
            history.append(item)
    return history, workflow_names


def _required_check_names(
    governance: Sequence[Mapping[str, Any]],
) -> set[str]:
    """Backward-compatible wrapper over normalized required-check policy parsing."""
    return required_check_names(governance)

def _blind_spots(coverage: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {
            "domain": domain,
            "summary": f"Audit coverage for {domain} is {state}; no broader assurance claim is made for this domain.",
        }
        for domain, state in sorted(coverage.items())
        if state not in {"VERIFIED", "NOT_APPLICABLE"}
    ]




def _resolve_runner_baselines(
    workflow_sources: Sequence[Mapping[str, Any]],
    supplied_evidence: Sequence[Mapping[str, Any]],
    *,
    as_of: datetime,
    max_age_days: int = 7,
) -> list[dict[str, Any]]:
    """Match supplied authoritative evidence to runner lifecycle requests."""
    if not supplied_evidence:
        return []
    resolved: list[dict[str, Any]] = []
    for request in build_runner_baseline_requests(workflow_sources):
        match = match_baseline_request(
            request,
            supplied_evidence,
            as_of=as_of,
            max_age_days=max_age_days,
        )
        if match is not None:
            item = dict(match)
            validate_document("baseline-evidence.v1", item)
            resolved.append(item)
    return resolved


def _audit(
    repo: Path,
    *,
    target: str | None,
    mode: str,
    history_days: int | None,
    max_runs: int | None,
    offline: bool,
    no_current_baseline: bool,
    baseline_evidence: Sequence[Mapping[str, Any]] = (),
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    started_at = _now()
    plan, discovery = _build_plan(repo, target=target, mode=mode)
    repository = discovery["repository"]
    snapshot = discovery["snapshot"]
    profile = discovery["profile"]
    full_name = repository["full_name"]
    target_sha = snapshot["target_commit_sha"]
    target_branch = snapshot["target_branch"]

    evidence: list[dict[str, Any]] = [
        *discovery["identity_evidence"],
        *discovery["snapshot_evidence"],
    ]
    control_results: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    control_results.extend(evaluate_snapshot(evidence))

    profile_evidence = collect_repository_profile_evidence(
        repository=full_name,
        target_commit_sha=target_sha,
        profile=profile,
    )
    evidence.extend(profile_evidence)
    control_results.extend(evaluate_repository_profile(profile_evidence[0]))

    workflow_sources = collect_workflow_sources(
        repo,
        repository=full_name,
        target_commit_sha=target_sha,
    )
    evidence.extend(workflow_sources)
    if profile.get("github_actions"):
        actionlint_evidence = collect_actionlint_evidence(
            repo,
            repository=full_name,
            target_commit_sha=target_sha,
        )
        evidence.extend(actionlint_evidence)

        resolved_baselines = []
        if not no_current_baseline:
            resolved_baselines = _resolve_runner_baselines(
                workflow_sources,
                baseline_evidence,
                as_of=datetime.now(timezone.utc),
            )
        control_results.extend(
            evaluate_ci_static(
                workflow_sources,
                baseline_evidence=resolved_baselines,
                specialist_evidence=actionlint_evidence,
            )
        )

    if repository.get("owner") != "local" and not offline:
        governance = _governance_evidence(full_name, target_branch, target_sha)
        evidence.extend(governance)
        control_results.extend(evaluate_governance(governance))

        github_checks = next(
            (item for item in governance if item.get("id") == "ev_github_checks"),
            None,
        )
        provider_evidence: list[dict[str, Any]] = []
        provider_states: list[dict[str, Any]] = []
        if github_checks is not None:
            provider_discovery = collect_provider_discovery(github_checks)
            provider_states = collect_provider_states(
                github_checks,
                required_checks=required_check_requirements(governance),
            )
            provider_evidence = [provider_discovery, *provider_states]
            evidence.extend(provider_evidence)
        control_results.extend(evaluate_providers(provider_evidence))
        providers = provider_summaries(provider_states)

        security_evidence = _github_security_evidence(full_name, target_sha)
        evidence.extend(security_evidence)
        control_results.extend(
            evaluate_github_security([*governance, *security_evidence])
        )

        if profile.get("github_actions"):
            budget = plan["budgets"]["github"]
            history, _workflow_names = _actions_history_evidence(
                repository=full_name,
                sha=target_sha,
                max_days=history_days or int(budget["max_history_days"]),
                max_runs=max_runs or int(budget["max_runs_per_workflow"]),
            )
            evidence.extend(history)

            gate_mapping_evidence = build_required_gate_mapping_evidence(
                repository=full_name,
                target_commit_sha=target_sha,
                governance=governance,
                history=history,
            )
            evidence.append(gate_mapping_evidence)
            gate_mapping = gate_mapping_evidence["observation"]
            required_workflow_ids = {
                str(item)
                for item in gate_mapping.get("required_workflow_ids", [])
                if item
            }

            if history:
                control_results.extend(
                    evaluate_ci_operational(
                        history,
                        required_workflow_ids=required_workflow_ids,
                        required_mapping_complete=bool(
                            gate_mapping.get("complete")
                        ),
                        required_gate_evidence_id=str(
                            gate_mapping_evidence["id"]
                        ),
                        expected_blocking_workflow_ids=None,
                    )
                )

    hygiene_evidence = [
        *collect_branches(repo, target_ref=target_branch),
        *collect_worktrees(repo, target_ref=target_branch),
        *collect_stashes(repo, target_ref=target_branch),
    ]
    evidence.extend(hygiene_evidence)
    control_results.extend(
        evaluate_hygiene(
            hygiene_evidence,
            default_branch=target_branch,
        )
    )

    candidates = correlate(control_results=control_results, evidence=evidence)
    groups = deduplicate_candidates(candidates)
    baseline_as_of = datetime.now(timezone.utc).date().isoformat()
    findings = materialize_findings(groups, baseline_as_of=baseline_as_of)
    remediation_tracks = build_remediation_tracks(findings)
    coverage = compute_domain_coverage(
        audit_plan=plan,
        control_results=control_results,
        evidence=evidence,
    )

    report = build_audit_report(
        audit_id=str(plan["audit_id"]),
        mode=mode,
        started_at=started_at,
        completed_at=_now(),
        baseline_as_of=baseline_as_of,
        repository=repository,
        snapshot=snapshot,
        profile=profile,
        audit_plan=plan,
        coverage=coverage,
        control_results=control_results,
        providers=providers,
        findings=findings,
        observations=[],
        blind_spots=_blind_spots(coverage),
        remediation_tracks=remediation_tracks,
    )
    assert_no_secret_values(report)
    return plan, report, evidence


def _write_audit_outputs(
    *,
    output_dir: Path,
    plan: Mapping[str, Any],
    report: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    output_format: str,
    debug_evidence: bool,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    plan_path = output_dir / "audit-plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary: dict[str, str] = {
        "output_dir": str(output_dir),
        "plan": str(plan_path),
    }
    if output_format in {"json", "both"}:
        report_json = output_dir / "audit-report.json"
        report_json.write_text(render_json(report), encoding="utf-8")
        summary["report_json"] = str(report_json)
    if output_format in {"markdown", "both"}:
        report_markdown = output_dir / "audit-report.md"
        report_markdown.write_text(render_markdown(report), encoding="utf-8")
        summary["report_markdown"] = str(report_markdown)
    if debug_evidence:
        debug_path = output_dir / "evidence.json"
        debug_path.write_text(json.dumps(list(evidence), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert_no_secret_values(json.loads(debug_path.read_text(encoding="utf-8")))
        summary["debug_evidence"] = str(debug_path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repo-assurance")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Discover repository identity and capabilities")
    discover.add_argument("--repo", type=Path, default=Path("."))
    discover.add_argument("--target")

    plan = subparsers.add_parser("plan", help="Build the repository-specific audit plan")
    plan.add_argument("--repo", type=Path, default=Path("."))
    plan.add_argument("--target")
    plan.add_argument("--mode", choices=["quick", "standard", "deep"], default="standard")

    audit = subparsers.add_parser("audit", help="Run a read-only repository assurance audit")
    audit.add_argument("--repo", type=Path, default=Path("."))
    audit.add_argument("--target")
    audit.add_argument("--mode", choices=["quick", "standard", "deep"], default="standard")
    audit.add_argument("--output", type=Path)
    audit.add_argument("--history-days", type=int)
    audit.add_argument("--max-runs", type=int)
    audit.add_argument("--offline", action="store_true")
    audit.add_argument("--no-current-baseline", action="store_true")
    audit.add_argument("--baseline-evidence", type=Path, help="JSON baseline-evidence/v1 object or list from authoritative current sources")
    audit.add_argument("--debug-evidence", action="store_true")
    audit.add_argument("--format", choices=["json", "markdown", "both"], default="both")

    validate = subparsers.add_parser("validate", help="Validate a canonical JSON artifact")
    validate.add_argument("artifact_type", choices=["report", "plan", "finding", "evidence", "control"])
    validate.add_argument("path", type=Path)

    render = subparsers.add_parser("render", help="Render a canonical audit report")
    render.add_argument("path", type=Path)
    render.add_argument("--format", choices=["json", "markdown"], default="markdown")

    return parser


def _schema_for_artifact(artifact_type: str) -> str:
    return {
        "report": "audit-report.v1",
        "plan": "audit-plan.v1",
        "finding": "finding.v1",
        "evidence": "evidence.v1",
        "control": "control.v1",
    }[artifact_type]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    if args.command == "discover":
        discovery = _discover(args.repo.resolve(), args.target)
        payload = {
            "repository": discovery["repository"],
            "snapshot": discovery["snapshot"],
            "profile": discovery["profile"],
            "capabilities": discovery["capabilities"],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "plan":
        plan, _ = _build_plan(args.repo.resolve(), target=args.target, mode=args.mode)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if args.command == "audit":
        repo = args.repo.resolve()
        supplied_baseline_evidence = (
            load_baseline_evidence(args.baseline_evidence)
            if args.baseline_evidence is not None
            else []
        )
        plan, report, evidence = _audit(
            repo,
            target=args.target,
            mode=args.mode,
            history_days=args.history_days,
            max_runs=args.max_runs,
            offline=args.offline,
            no_current_baseline=args.no_current_baseline,
            baseline_evidence=supplied_baseline_evidence,
        )
        output_dir = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="repo-assurance-"))
        summary = _write_audit_outputs(
            output_dir=output_dir,
            plan=plan,
            report=report,
            evidence=evidence,
            output_format=args.format,
            debug_evidence=args.debug_evidence,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if args.command == "validate":
        payload = json.loads(args.path.read_text(encoding="utf-8"))
        if args.artifact_type == "control" and isinstance(payload, dict) and payload.get("schema_version") == "control-catalog/v1":
            validate_catalog_document(payload, source_name=args.path.name)
        else:
            validate_document(_schema_for_artifact(args.artifact_type), payload)
        print(f"valid: {args.artifact_type}")
        return 0

    if args.command == "render":
        payload = json.loads(args.path.read_text(encoding="utf-8"))
        validate_document("audit-report.v1", payload)
        if args.format == "json":
            print(render_json(payload), end="")
        else:
            print(render_markdown(payload), end="")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
