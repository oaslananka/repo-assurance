from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from repo_assurance.collectors.github_actions import (
    collect_workflow_history,
    collect_workflows,
    summarize_workflow_history,
)


class QueueRunner:
    def __init__(self, results: list[subprocess.CompletedProcess[str]]) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.results.pop(0)


def cp(payload=None, *, returncode: int = 0, stderr: str = ""):
    stdout = "" if payload is None else json.dumps(payload)
    return subprocess.CompletedProcess(["gh"], returncode, stdout, stderr)


NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def run(run_id: int, created_at: str, conclusion: str, *, sha: str = "a" * 40, attempt: int = 1) -> dict:
    return {
        "id": run_id,
        "head_sha": sha,
        "run_attempt": attempt,
        "status": "completed",
        "conclusion": conclusion,
        "event": "pull_request",
        "created_at": created_at,
        "updated_at": created_at,
        "run_started_at": created_at,
    }


def test_collect_workflows_normalizes_inventory() -> None:
    runner = QueueRunner([cp({
        "total_count": 2,
        "workflows": [
            {"id": 10, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"},
            {"id": 20, "name": "Nightly", "path": ".github/workflows/nightly.yml", "state": "disabled_manually", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-08-01T00:00:00Z"},
        ],
    })])

    evidence = collect_workflows("acme/demo", "a" * 40, runner=runner)

    assert evidence[0]["observation"]["access_state"] == "AVAILABLE"
    assert [item["id"] for item in evidence[0]["observation"]["workflows"]] == [10, 20]


def test_history_paginates_until_empty_page() -> None:
    runner = QueueRunner([
        cp({"workflow_runs": [
            run(3, "2026-10-02T10:00:00Z", "success"),
            run(2, "2026-10-01T10:00:00Z", "failure"),
        ]}),
        cp({"workflow_runs": [
            run(1, "2026-09-30T10:00:00Z", "success"),
        ]}),
        cp({"workflow_runs": []}),
    ])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id="10",
        target_commit_sha="a" * 40,
        max_days=90,
        max_runs=100,
        runner=runner,
        now=NOW,
    )

    assert len(evidence[0]["observation"]["runs"]) == 3
    assert evidence[0]["visibility"]["completeness"] == "complete"
    assert len(runner.calls) == 3


def test_history_stops_at_time_cutoff() -> None:
    runner = QueueRunner([cp({"workflow_runs": [
        run(3, "2026-10-02T10:00:00Z", "success"),
        run(2, "2026-09-20T10:00:00Z", "failure"),
        run(1, "2026-08-01T10:00:00Z", "failure"),
    ]})])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id="10",
        target_commit_sha="a" * 40,
        max_days=30,
        max_runs=100,
        runner=runner,
        now=NOW,
    )

    assert [item["id"] for item in evidence[0]["observation"]["runs"]] == [3, 2]
    assert evidence[0]["observation"]["stopped_by_cutoff"] is True


def test_run_limit_marks_history_partial() -> None:
    runner = QueueRunner([cp({"workflow_runs": [
        run(3, "2026-10-02T10:00:00Z", "failure"),
        run(2, "2026-10-01T10:00:00Z", "failure"),
        run(1, "2026-09-30T10:00:00Z", "success"),
    ]})])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id="10",
        target_commit_sha="a" * 40,
        max_days=90,
        max_runs=2,
        runner=runner,
        now=NOW,
    )

    assert len(evidence[0]["observation"]["runs"]) == 2
    assert evidence[0]["observation"]["truncated_by_run_limit"] is True
    assert evidence[0]["visibility"]["completeness"] == "partial"


def test_known_retention_shorter_than_requested_marks_retention_limited() -> None:
    runner = QueueRunner([cp({"workflow_runs": []})])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id="10",
        target_commit_sha="a" * 40,
        max_days=180,
        max_runs=100,
        runner=runner,
        now=NOW,
        known_retention_days=90,
    )

    assert evidence[0]["visibility"]["retention_limited"] is True
    assert evidence[0]["visibility"]["completeness"] == "partial"


def test_permission_error_is_explicit_unknown_not_empty_history() -> None:
    runner = QueueRunner([
        subprocess.CompletedProcess(
            ["gh"], 1, "", "gh: Resource not accessible (HTTP 403)"
        )
    ])

    evidence = collect_workflow_history(
        repository="acme/demo",
        workflow_id="10",
        target_commit_sha="a" * 40,
        max_days=90,
        max_runs=100,
        runner=runner,
        now=NOW,
    )

    assert evidence[0]["observation"]["access_state"] == "UNKNOWN_PERMISSION"
    assert evidence[0]["visibility"]["permission_limited"] is True
    assert evidence[0]["visibility"]["completeness"] == "unknown"


def test_summary_counts_outcomes_and_consecutive_failures() -> None:
    history = {
        "observation": {
            "runs": [
                run(5, "2026-10-02T10:00:00Z", "failure"),
                run(4, "2026-10-01T10:00:00Z", "failure"),
                run(3, "2026-09-30T10:00:00Z", "success"),
                run(2, "2026-09-29T10:00:00Z", "cancelled"),
                run(1, "2026-09-28T10:00:00Z", "skipped"),
            ]
        },
        "visibility": {"retention_limited": False},
    }

    summary = summarize_workflow_history(history)

    assert summary["runs_analyzed"] == 5
    assert summary["failure"] == 2
    assert summary["success"] == 1
    assert summary["cancelled"] == 1
    assert summary["skipped"] == 1
    assert summary["consecutive_failures"] == 2
    assert summary["last_run"] == "2026-10-02T10:00:00Z"
    assert summary["last_success"] == "2026-09-30T10:00:00Z"


@pytest.mark.parametrize("max_days,max_runs", [(0, 10), (30, 0)])
def test_history_requires_positive_bounds(max_days: int, max_runs: int) -> None:
    with pytest.raises(ValueError):
        collect_workflow_history(
            repository="acme/demo",
            workflow_id="10",
            target_commit_sha="a" * 40,
            max_days=max_days,
            max_runs=max_runs,
            runner=QueueRunner([]),
            now=NOW,
        )
