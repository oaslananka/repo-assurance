from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from repo_assurance.core.schema import validate_document


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find(evidence: Sequence[dict[str, Any]], evidence_id: str) -> dict[str, Any] | None:
    return next((item for item in evidence if item.get("id") == evidence_id), None)


def _access_state(item: dict[str, Any] | None) -> str:
    if not item:
        return "UNAVAILABLE"
    observation = item.get("observation")
    if not isinstance(observation, dict):
        return "UNKNOWN_ERROR"
    return str(observation.get("access_state", "UNKNOWN_ERROR"))


def _control_state_for_access(access: str) -> str:
    if access in {"UNKNOWN_PERMISSION", "AUTH_FAILED"}:
        return "UNKNOWN_PERMISSION"
    if access in {"UNKNOWN_ERROR"}:
        return "UNKNOWN_ERROR"
    if access in {"UNAVAILABLE"}:
        return "UNAVAILABLE"
    return "INCONCLUSIVE"


def _result(
    control_id: str,
    state: str,
    subject: dict[str, Any],
    evidence_ids: Iterable[str],
    *,
    reason: str | None = None,
    candidates: Iterable[str] = (),
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": subject,
        "evidence_ids": sorted(set(evidence_ids)),
        "candidate_finding_ids": sorted(set(candidates)),
        "evaluated_at": _now(),
    }
    if reason:
        result["reason"] = reason
    validate_document("control-result.v1", result)
    return result


def _active_default_rulesets(ruleset_evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not ruleset_evidence or _access_state(ruleset_evidence) != "AVAILABLE":
        return []
    observation = ruleset_evidence.get("observation", {})
    rulesets = observation.get("rulesets", []) if isinstance(observation, dict) else []
    active: list[dict[str, Any]] = []
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            continue
        if ruleset.get("enforcement") != "active" or ruleset.get("target") != "branch":
            continue
        conditions = ruleset.get("conditions")
        if not conditions:
            active.append(ruleset)
            continue
        if not isinstance(conditions, dict):
            continue
        ref_name = conditions.get("ref_name")
        if not isinstance(ref_name, dict):
            continue
        includes = ref_name.get("include") or []
        excludes = ref_name.get("exclude") or []
        if "~DEFAULT_BRANCH" in includes and "~DEFAULT_BRANCH" not in excludes:
            active.append(ruleset)
    return active


def _ruleset_required_checks(rulesets: Sequence[dict[str, Any]]) -> set[str]:
    required: set[str] = set()
    for ruleset in rulesets:
        rules = ruleset.get("rules") or []
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
                continue
            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                continue
            checks = parameters.get("required_status_checks") or []
            if not isinstance(checks, list):
                continue
            for check in checks:
                if isinstance(check, dict) and check.get("context"):
                    required.add(str(check["context"]))
    return required


def evaluate_governance(evidence: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    repository = _find(evidence, "ev_github_repository")
    branch = _find(evidence, "ev_github_default_branch")
    rulesets_evidence = _find(evidence, "ev_github_rulesets")
    checks_evidence = _find(evidence, "ev_github_checks")
    subject = (
        (repository or branch or rulesets_evidence or checks_evidence or {}).get("subject")
        or {"type": "repository", "identifier": "unknown"}
    )

    repository_access = _access_state(repository)
    branch_access = _access_state(branch)
    rulesets_access = _access_state(rulesets_evidence)
    active_rulesets = _active_default_rulesets(rulesets_evidence)

    branch_observation = branch.get("observation", {}) if branch else {}
    protected = bool(branch_observation.get("protected")) if isinstance(branch_observation, dict) and branch_access == "AVAILABLE" else False

    governance_evidence = [item["id"] for item in (branch, rulesets_evidence) if item]
    if protected or active_rulesets:
        gov_001 = _result("GH-GOV-001", "PASS", subject, governance_evidence)
    elif rulesets_access != "AVAILABLE":
        gov_001 = _result(
            "GH-GOV-001",
            _control_state_for_access(rulesets_access),
            subject,
            governance_evidence,
            reason="ruleset_visibility_incomplete",
        )
    elif branch_access != "AVAILABLE":
        gov_001 = _result(
            "GH-GOV-001",
            _control_state_for_access(branch_access),
            subject,
            governance_evidence,
            reason="default_branch_visibility_incomplete",
        )
    else:
        gov_001 = _result(
            "GH-GOV-001",
            "FINDING",
            subject,
            governance_evidence,
            reason="default_branch_governance_absent",
            candidates=["candidate_GH-GOV-001_default_branch_governance"],
        )

    required_checks: set[str] = set()
    if isinstance(branch_observation, dict) and branch_access == "AVAILABLE":
        required_checks.update(str(item) for item in branch_observation.get("required_status_checks", []) if item)
    required_checks.update(_ruleset_required_checks(active_rulesets))

    required_evidence = [item["id"] for item in (branch, rulesets_evidence, checks_evidence) if item]
    if rulesets_access != "AVAILABLE":
        gov_003 = _result(
            "GH-GOV-003",
            _control_state_for_access(rulesets_access),
            subject,
            required_evidence,
            reason="ruleset_visibility_incomplete",
        )
    elif required_checks and not checks_evidence:
        gov_003 = _result(
            "GH-GOV-003",
            "INCONCLUSIVE",
            subject,
            required_evidence,
            reason="produced_checks_not_observed",
        )
    else:
        produced: set[str] = set()
        if checks_evidence:
            checks_observation = checks_evidence.get("observation", {})
            if isinstance(checks_observation, dict):
                produced.update(str(item) for item in checks_observation.get("check_names", []) if item)
        stale = sorted(required_checks - produced) if checks_evidence else []
        if stale:
            gov_003 = _result(
                "GH-GOV-003",
                "FINDING",
                subject,
                required_evidence,
                reason=f"stale_required_checks:{','.join(stale)}",
                candidates=["candidate_GH-GOV-003_stale_required_checks"],
            )
        else:
            gov_003 = _result(
                "GH-GOV-003",
                "PASS",
                subject,
                required_evidence,
                reason="required_checks:none" if not required_checks else None,
            )

    bypass_evidence = [rulesets_evidence["id"]] if rulesets_evidence else []
    if rulesets_access != "AVAILABLE":
        gov_007 = _result(
            "GH-GOV-007",
            _control_state_for_access(rulesets_access),
            subject,
            bypass_evidence,
            reason="ruleset_visibility_incomplete",
        )
    else:
        always_bypass = [
            actor
            for ruleset in active_rulesets
            for actor in (ruleset.get("bypass_actors") or [])
            if isinstance(actor, dict) and actor.get("bypass_mode") == "always"
        ]
        if always_bypass:
            gov_007 = _result(
                "GH-GOV-007",
                "FINDING",
                subject,
                bypass_evidence,
                reason=f"always_bypass_actors:{len(always_bypass)}",
                candidates=["candidate_GH-GOV-007_bypass_exposure"],
            )
        else:
            gov_007 = _result("GH-GOV-007", "PASS", subject, bypass_evidence)

    repo_evidence = [repository["id"]] if repository else []
    if repository_access != "AVAILABLE":
        gov_008 = _result(
            "GH-GOV-008",
            _control_state_for_access(repository_access),
            subject,
            repo_evidence,
            reason="repository_settings_visibility_incomplete",
        )
    else:
        repository_observation = repository.get("observation", {}) if repository else {}
        enabled = bool(repository_observation.get("delete_branch_on_merge")) if isinstance(repository_observation, dict) else False
        gov_008 = _result(
            "GH-GOV-008",
            "PASS",
            subject,
            repo_evidence,
            reason=f"auto_delete_merged_branches:{'enabled' if enabled else 'disabled'}",
        )

    return [gov_001, gov_003, gov_007, gov_008]
