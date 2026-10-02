from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


_CONTROL_IDS = (
    "CI-OPS-001",
    "CI-OPS-002",
    "CI-OPS-003",
    "CI-OPS-005",
    "CI-OPS-006",
    "CI-OPS-007",
    "CI-OPS-008",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _result(
    control_id: str,
    state: str,
    subject: Mapping[str, Any],
    evidence_id: str,
    *,
    reason: str | None = None,
    candidate: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": dict(subject),
        "evidence_ids": [evidence_id],
        "candidate_finding_ids": [candidate] if candidate else [],
        "evaluated_at": _now(),
    }
    if reason:
        item["reason"] = reason
    validate_document("control-result.v1", item)
    return item


def _access_failure_results(item: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    observation = item.get("observation")
    if not isinstance(observation, Mapping):
        state = "UNKNOWN_ERROR"
        reason = "workflow_history_observation_invalid"
    else:
        access = str(observation.get("access_state", "AVAILABLE"))
        if access == "AVAILABLE" or access == "PARTIAL":
            return None
        if access in {"UNKNOWN_PERMISSION", "AUTH_FAILED"}:
            state = "UNKNOWN_PERMISSION"
        elif access == "UNAVAILABLE":
            state = "UNAVAILABLE"
        else:
            state = "UNKNOWN_ERROR"
        reason = f"workflow_history_access:{access}"

    subject = item.get("subject")
    if not isinstance(subject, Mapping):
        subject = {"type": "github_workflow", "identifier": "unknown"}
    evidence_id = str(item.get("id", "unknown"))
    return [_result(control_id, state, subject, evidence_id, reason=reason) for control_id in _CONTROL_IDS]


def _runs(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    observation = item.get("observation")
    if not isinstance(observation, Mapping):
        return []
    runs = observation.get("runs")
    return [dict(run) for run in runs if isinstance(run, Mapping)] if isinstance(runs, list) else []


def _expected_execution(item: Mapping[str, Any]) -> bool:
    observation = item.get("observation")
    return bool(observation.get("expected_execution")) if isinstance(observation, Mapping) else False


def _workflow_id(item: Mapping[str, Any]) -> str:
    observation = item.get("observation")
    if isinstance(observation, Mapping) and observation.get("workflow_id") is not None:
        return str(observation["workflow_id"])
    subject = item.get("subject")
    if isinstance(subject, Mapping):
        return str(subject.get("identifier", "unknown"))
    return "unknown"


def _outcome_stats(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = {"success": 0, "failure": 0, "cancelled": 0, "skipped": 0}
    for run in runs:
        conclusion = str(run.get("conclusion", ""))
        if conclusion in counts:
            counts[conclusion] += 1

    meaningful = counts["success"] + counts["failure"]
    failure_rate = counts["failure"] / meaningful if meaningful else 0.0
    success_rate = counts["success"] / meaningful if meaningful else 0.0

    consecutive_failures = 0
    for run in runs:
        conclusion = run.get("conclusion")
        if conclusion == "failure":
            consecutive_failures += 1
        else:
            break

    return {
        **counts,
        "runs": len(runs),
        "meaningful": meaningful,
        "failure_rate": failure_rate,
        "success_rate": success_rate,
        "consecutive_failures": consecutive_failures,
    }


def _rerun_recovery_sha(runs: Sequence[Mapping[str, Any]]) -> str | None:
    by_sha: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for run in runs:
        sha = run.get("head_sha")
        if isinstance(sha, str) and sha:
            by_sha[sha].append(run)

    for sha in sorted(by_sha):
        attempts = by_sha[sha]
        conclusions = {str(run.get("conclusion")) for run in attempts}
        attempt_numbers = {
            int(run.get("run_attempt"))
            for run in attempts
            if isinstance(run.get("run_attempt"), int)
        }
        if "failure" in conclusions and "success" in conclusions and len(attempt_numbers) >= 2:
            return sha
    return None


def _last_run_time(runs: Sequence[Mapping[str, Any]]) -> datetime | None:
    times = [_parse_time(run.get("created_at")) for run in runs]
    valid = [value for value in times if value is not None]
    return max(valid) if valid else None


def _evaluate_one(
    item: Mapping[str, Any],
    *,
    required_workflow_ids: set[str],
    expected_blocking_workflow_ids: set[str] | None,
    now: datetime,
    stale_after_days: int,
) -> list[dict[str, Any]]:
    access_results = _access_failure_results(item)
    if access_results is not None:
        return access_results

    subject = item.get("subject")
    if not isinstance(subject, Mapping):
        subject = {"type": "github_workflow", "identifier": _workflow_id(item)}
    evidence_id = str(item.get("id", "unknown"))
    workflow_id = _workflow_id(item)
    runs = _runs(item)
    expected_execution = _expected_execution(item)
    stats = _outcome_stats(runs)

    last_run = _last_run_time(runs)
    if not runs:
        freshness = _result(
            "CI-OPS-001", "INCONCLUSIVE", subject, evidence_id,
            reason="no_observed_runs",
        )
    elif expected_execution and last_run and last_run < now - timedelta(days=stale_after_days):
        freshness = _result(
            "CI-OPS-001", "FINDING", subject, evidence_id,
            reason=f"workflow_execution_stale:last_run={last_run.isoformat().replace('+00:00', 'Z')}",
            candidate=f"candidate_CI-OPS-001_{workflow_id}_stale",
        )
    else:
        freshness = _result("CI-OPS-001", "PASS", subject, evidence_id)

    if runs:
        distribution = _result(
            "CI-OPS-002", "PASS", subject, evidence_id,
            reason=(
                "outcomes:"
                f"success={stats['success']},failure={stats['failure']},"
                f"cancelled={stats['cancelled']},skipped={stats['skipped']}"
            ),
        )
    else:
        distribution = _result(
            "CI-OPS-002", "INCONCLUSIVE", subject, evidence_id,
            reason="no_observed_runs",
        )

    chronic = bool(
        (stats["meaningful"] >= 5 and stats["failure_rate"] >= 0.50)
        or stats["consecutive_failures"] >= 5
    )
    if chronic:
        chronic_result = _result(
            "CI-OPS-003", "FINDING", subject, evidence_id,
            reason=(
                f"chronic_failure:runs={stats['meaningful']},"
                f"failure_rate={stats['failure_rate']:.3f},"
                f"consecutive_failures={stats['consecutive_failures']}"
            ),
            candidate=f"candidate_CI-OPS-003_{workflow_id}_chronic_failure",
        )
    elif stats["meaningful"]:
        chronic_result = _result("CI-OPS-003", "PASS", subject, evidence_id)
    else:
        chronic_result = _result(
            "CI-OPS-003", "INCONCLUSIVE", subject, evidence_id,
            reason="insufficient_meaningful_runs",
        )

    recovery_sha = _rerun_recovery_sha(runs)
    if recovery_sha:
        flaky_result = _result(
            "CI-OPS-005", "FINDING", subject, evidence_id,
            reason=f"rerun_recovery:{recovery_sha}",
            candidate=f"candidate_CI-OPS-005_{workflow_id}_rerun_recovery",
        )
    elif len(runs) >= 2:
        flaky_result = _result("CI-OPS-005", "PASS", subject, evidence_id)
    else:
        flaky_result = _result(
            "CI-OPS-005", "INCONCLUSIVE", subject, evidence_id,
            reason="insufficient_runs_for_flakiness",
        )

    if workflow_id not in required_workflow_ids:
        unreliable_gate = _result(
            "CI-OPS-006", "PASS", subject, evidence_id,
            reason="workflow_not_required",
        )
    elif chronic or recovery_sha:
        unreliable_gate = _result(
            "CI-OPS-006", "FINDING", subject, evidence_id,
            reason=f"required_gate_unreliable:{workflow_id}",
            candidate=f"candidate_CI-OPS-006_{workflow_id}_unreliable_gate",
        )
    else:
        unreliable_gate = _result("CI-OPS-006", "PASS", subject, evidence_id)

    if expected_blocking_workflow_ids is None:
        unenforced = _result(
            "CI-OPS-007", "INCONCLUSIVE", subject, evidence_id,
            reason="blocking_expectation_unknown",
        )
    elif workflow_id not in expected_blocking_workflow_ids:
        unenforced = _result(
            "CI-OPS-007", "PASS", subject, evidence_id,
            reason="workflow_not_expected_blocking",
        )
    elif workflow_id in required_workflow_ids:
        unenforced = _result(
            "CI-OPS-007", "PASS", subject, evidence_id,
            reason="workflow_required",
        )
    elif stats["meaningful"] >= 5 and stats["success_rate"] >= 0.80 and not chronic:
        unenforced = _result(
            "CI-OPS-007", "FINDING", subject, evidence_id,
            reason=f"healthy_expected_gate_not_required:{workflow_id}",
            candidate=f"candidate_CI-OPS-007_{workflow_id}_unenforced",
        )
    else:
        unenforced = _result(
            "CI-OPS-007", "INCONCLUSIVE", subject, evidence_id,
            reason="expected_gate_not_healthy_enough_to_assess_enforcement",
        )

    if not runs and expected_execution:
        dead = _result(
            "CI-OPS-008", "FINDING", subject, evidence_id,
            reason="expected_workflow_has_no_observed_runs",
            candidate=f"candidate_CI-OPS-008_{workflow_id}_dead",
        )
    elif not runs:
        dead = _result(
            "CI-OPS-008", "INCONCLUSIVE", subject, evidence_id,
            reason="workflow_execution_expectation_absent",
        )
    elif len(runs) >= 5 and stats["skipped"] == len(runs):
        dead = _result(
            "CI-OPS-008", "FINDING", subject, evidence_id,
            reason="all_observed_runs_skipped",
            candidate=f"candidate_CI-OPS-008_{workflow_id}_skipped",
        )
    else:
        dead = _result("CI-OPS-008", "PASS", subject, evidence_id)

    return [
        freshness,
        distribution,
        chronic_result,
        flaky_result,
        unreliable_gate,
        unenforced,
        dead,
    ]


def evaluate_ci_operational(
    history_evidence: Sequence[Mapping[str, Any]],
    *,
    required_workflow_ids: set[str] | None = None,
    expected_blocking_workflow_ids: set[str] | None = None,
    now: datetime | None = None,
    stale_after_days: int = 30,
) -> list[dict[str, Any]]:
    if stale_after_days <= 0:
        raise ValueError("stale_after_days must be positive")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    required = set(required_workflow_ids or set())
    results: list[dict[str, Any]] = []
    for item in history_evidence:
        results.extend(
            _evaluate_one(
                item,
                required_workflow_ids=required,
                expected_blocking_workflow_ids=expected_blocking_workflow_ids,
                now=current,
                stale_after_days=stale_after_days,
            )
        )
    return results
