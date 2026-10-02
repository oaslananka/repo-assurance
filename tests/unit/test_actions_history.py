from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

from repo_assurance.collectors.github_actions import (
    collect_workflow_history,
    collect_workflows,
    summarize_workflow_history,
)


class SequenceRunner:
    def __init__(self, results: list[subprocess.CompletedProcess[str]]) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.results.pop(0)


def cp(payload, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess(["gh"], returncode, stdout, stderr)


def run(run_id: int, created_at: str, conclusion: str, *, sha: str = "a" * 40, attempt: int = 1) -> dict:
    return {
        "id": run_id,
        "head_sha": sha,
        "run_attempt": attempt,
        "status": "completed",
        "conclusion": conclusion,
        "event": "push",
        "created_at": created_at,
        "updated_at": created_at,
        "run_started_at": created_at,
    }


def test_collect_workflows_normalizes_workflow_inventory() -> None:
    runner = SequenceRunner([cp({"workflows": [
        {"id": 10, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
        {"id": 20, "name": "Nightly", "path": ".github/workflows/nightly.yml", "state": "disabled_manually"},
    ]})])

    evidence = collect_workflows("acme/demo", "a" * 40, runner=runner)

    assert runner.calls == [["gh", "api", "/repos/acme/demo/actions/workflows?per_page=100"]]
    assert [item["id"] for item in evidence[0]["observation"]["workflows"]] == [10, 20]
    assert evidence[0]["observation"]["workflows"][1]["state"] == "disabled_manually"


def test_history_paginates_until_max_runs() -> None:
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    first = [run(i, "2026-10-01T12:00:00Z", "success") for i in range(1, 101)]
    second = [run(i, "2026-09-30T12:00:00Z", "failure") for i in range(101, 181)]
    runner = SequenceRunner([
        cp({"total_count": 180, "workflow_runs": first}),
        cp({"total_count": 180, "workflow_runs": second}),
    ])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id=10,
        target_commit_sha="a" * 40,
        max_days=90,
        max_runs=150,
        runner=runner,
        now=now,
    )

    observation = evidence[0]["observation"]
    assert len(observation["runs"]) == 150
    assert observation["truncated_by_run_limit"] is True
    assert len(runner.calls) == 2
    assert runner.calls[1][-1].endswith("page=2")


def test_history_stops_when_requested_time_window_is_covered() -> None:
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    runner = SequenceRunner([
        cp({"total_count": 3, "workflow_runs": [
            run(1, "2026-10-01T12:00:00Z", "failure"),
            run(2, "2026-09-15T12:00:00Z", "success"),
            run(3, "2026-08-01T12:00:00Z", "success"),
        ]})
    ])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id=10,
        target_commit_sha="a" * 40,
        max_days=30,
        max_runs=100,
        runner=runner,
        now=now,
    )

    observation = evidence[0]["observation"]
    assert [item["id"] for item in observation["runs"]] == [1, 2]
    assert observation["window_complete"] is True
    assert observation["truncated_by_run_limit"] is False
    assert len(runner.calls) == 1


def test_known_retention_limit_marks_visibility_partial() -> None:
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    runner = SequenceRunner([cp({"total_count": 1, "workflow_runs": [run(1, "2026-09-20T12:00:00Z", "success")]})])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id=10,
        target_commit_sha="a" * 40,
        max_days=180,
        max_runs=100,
        runner=runner,
        now=now,
        known_retention_days=90,
    )

    assert evidence[0]["visibility"]["completeness"] == "partial"
    assert evidence[0]["visibility"]["retention_limited"] is True
    assert evidence[0]["observation"]["retention_limited"] is True


def test_permission_error_is_explicit_history_evidence() -> None:
    runner = SequenceRunner([cp("", returncode=1, stderr="gh: Resource not accessible (HTTP 403)")])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id=10,
        target_commit_sha="a" * 40,
        max_days=90,
        max_runs=100,
        runner=runner,
    )

    assert evidence[0]["observation"] == {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"}
    assert evidence[0]["visibility"]["permission_limited"] is True


def test_summary_counts_outcomes_and_consecutive_failures() -> None:
    history = {
        "observation": {
            "access_state": "AVAILABLE",
            "runs": [
                run(5, "2026-10-02T10:00:00Z", "failure"),
                run(4, "2026-10-02T09:00:00Z", "failure"),
                run(3, "2026-10-02T08:00:00Z", "success"),
                run(2, "2026-10-02T07:00:00Z", "cancelled"),
                run(1, "2026-10-02T06:00:00Z", "skipped"),
            ],
        }
    }

    summary = summarize_workflow_history(history)

    assert summary["runs_analyzed"] == 5
    assert summary["success"] == 1
    assert summary["failure"] == 2
    assert summary["cancelled"] == 1
    assert summary["skipped"] == 1
    assert summary["consecutive_failures"] == 2
    assert summary["last_run"] == "2026-10-02T10:00:00Z"
    assert summary["last_success"] == "2026-10-02T08:00:00Z"
