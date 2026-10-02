from __future__ import annotations

from datetime import datetime, timezone

from repo_assurance.evaluators.cicd_operational import evaluate_ci_operational


NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def run(run_id: int, conclusion: str, created_at: str, *, sha: str | None = None, attempt: int = 1) -> dict:
    return {
        "id": run_id,
        "head_sha": sha or f"{run_id:040x}"[-40:],
        "run_attempt": attempt,
        "status": "completed",
        "conclusion": conclusion,
        "event": "pull_request",
        "created_at": created_at,
        "updated_at": created_at,
        "run_started_at": created_at,
    }


def history(workflow_id: str, runs: list[dict], *, expected_execution: bool = True) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": f"ev_history_{workflow_id}",
        "kind": "github_history",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "github_workflow", "identifier": workflow_id},
        "observation": {
            "access_state": "AVAILABLE",
            "workflow_id": workflow_id,
            "workflow_name": f"Workflow {workflow_id}",
            "expected_execution": expected_execution,
            "runs": runs,
        },
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def by_control(results: list[dict], control_id: str) -> dict:
    return next(item for item in results if item["control_id"] == control_id)


def recent_runs(conclusions: list[str], *, sha: str | None = None) -> list[dict]:
    days = [f"2026-10-{2 - index:02d}T10:00:00Z" if index <= 1 else f"2026-09-{30 - (index - 2):02d}T10:00:00Z" for index in range(len(conclusions))]
    return [run(index + 1, conclusion, days[index], sha=sha) for index, conclusion in enumerate(conclusions)]


def test_chronic_failure_candidate_when_failure_rate_is_high() -> None:
    runs = recent_runs(["failure"] * 8 + ["success"] * 2)

    results = evaluate_ci_operational([history("10", runs)], now=NOW)

    item = by_control(results, "CI-OPS-003")
    assert item["state"] == "FINDING"
    assert item["reason"] == "chronic_failure:runs=10,failure_rate=0.800,consecutive_failures=8"


def test_required_chronic_failure_becomes_unreliable_gate() -> None:
    runs = recent_runs(["failure"] * 8 + ["success"] * 2)

    results = evaluate_ci_operational(
        [history("10", runs)],
        required_workflow_ids={"10"},
        now=NOW,
    )

    item = by_control(results, "CI-OPS-006")
    assert item["state"] == "FINDING"
    assert item["reason"] == "required_gate_unreliable:10"


def test_optional_chronic_failure_does_not_claim_required_gate_risk() -> None:
    runs = recent_runs(["failure"] * 8 + ["success"] * 2)

    results = evaluate_ci_operational([history("10", runs)], required_workflow_ids=set(), now=NOW)

    item = by_control(results, "CI-OPS-006")
    assert item["state"] == "PASS"
    assert item["reason"] == "workflow_not_required"


def test_same_sha_failed_then_rerun_passed_is_flaky_signal() -> None:
    sha = "b" * 40
    runs = [
        run(2, "success", "2026-10-02T10:05:00Z", sha=sha, attempt=2),
        run(1, "failure", "2026-10-02T10:00:00Z", sha=sha, attempt=1),
    ]

    results = evaluate_ci_operational([history("10", runs)], now=NOW)

    item = by_control(results, "CI-OPS-005")
    assert item["state"] == "FINDING"
    assert item["reason"] == f"rerun_recovery:{sha}"


def test_healthy_expected_blocking_workflow_not_required_is_enforcement_gap() -> None:
    runs = recent_runs(["success"] * 10)

    results = evaluate_ci_operational(
        [history("10", runs)],
        required_workflow_ids=set(),
        expected_blocking_workflow_ids={"10"},
        now=NOW,
    )

    item = by_control(results, "CI-OPS-007")
    assert item["state"] == "FINDING"
    assert item["reason"] == "healthy_expected_gate_not_required:10"


def test_no_policy_context_does_not_invent_enforcement_gap() -> None:
    runs = recent_runs(["success"] * 10)

    results = evaluate_ci_operational([history("10", runs)], now=NOW)

    item = by_control(results, "CI-OPS-007")
    assert item["state"] == "INCONCLUSIVE"
    assert item["reason"] == "blocking_expectation_unknown"


def test_expected_workflow_with_no_runs_is_dead_workflow_finding() -> None:
    results = evaluate_ci_operational([history("10", [], expected_execution=True)], now=NOW)

    item = by_control(results, "CI-OPS-008")
    assert item["state"] == "FINDING"
    assert item["reason"] == "expected_workflow_has_no_observed_runs"


def test_no_runs_without_execution_expectation_is_inconclusive_not_dead() -> None:
    results = evaluate_ci_operational([history("10", [], expected_execution=False)], now=NOW)

    item = by_control(results, "CI-OPS-008")
    assert item["state"] == "INCONCLUSIVE"
    assert item["reason"] == "workflow_execution_expectation_absent"


def test_stale_last_execution_is_finding_only_when_expected_to_run() -> None:
    runs = [run(1, "success", "2026-07-01T10:00:00Z")]

    results = evaluate_ci_operational(
        [history("10", runs, expected_execution=True)],
        now=NOW,
        stale_after_days=30,
    )

    item = by_control(results, "CI-OPS-001")
    assert item["state"] == "FINDING"
    assert item["reason"].startswith("workflow_execution_stale:last_run=2026-07-01")


def test_permission_limited_history_propagates_unknown_permission() -> None:
    item = history("10", [])
    item["observation"] = {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403", "runs": []}
    item["visibility"]["completeness"] = "unknown"
    item["visibility"]["permission_limited"] = True

    results = evaluate_ci_operational([item], now=NOW)

    assert {result["state"] for result in results} == {"UNKNOWN_PERMISSION"}
