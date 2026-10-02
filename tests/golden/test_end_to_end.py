from __future__ import annotations

from datetime import datetime, timezone

from repo_assurance.core.correlation import correlate
from repo_assurance.core.dedupe import deduplicate_candidates
from repo_assurance.core.findings import materialize_findings
from repo_assurance.evaluators.cicd_operational import evaluate_ci_operational
from repo_assurance.evaluators.cicd_static import evaluate_ci_static
from repo_assurance.evaluators.governance import evaluate_governance
from repo_assurance.evaluators.hygiene import evaluate_hygiene

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)


def canonicalize(results: list[dict], evidence: list[dict]) -> list[dict]:
    return materialize_findings(
        deduplicate_candidates(correlate(control_results=results, evidence=evidence)),
        baseline_as_of="2026-10-02",
    )


def history_evidence(runs: list[dict], *, workflow_id: str = "10", access_state: str = "AVAILABLE") -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": f"ev_history_{workflow_id}",
        "kind": "github_history",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "github_workflow", "identifier": ".github/workflows/ci.yml"},
        "observation": {
            "access_state": access_state,
            "workflow_id": workflow_id,
            "workflow_name": "CI",
            "expected_execution": True,
            "runs": runs,
        },
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T12:00:00Z",
        "visibility": {
            "completeness": "complete" if access_state == "AVAILABLE" else "unknown",
            "permission_limited": access_state == "UNKNOWN_PERMISSION",
            "retention_limited": False,
        },
        "redactions": [],
    }


def run(run_id: int, conclusion: str, *, sha: str | None = None, attempt: int = 1) -> dict:
    day = max(1, 30 - run_id)
    return {
        "id": run_id,
        "head_sha": sha or format(run_id, "040x"),
        "run_attempt": attempt,
        "status": "completed",
        "conclusion": conclusion,
        "event": "pull_request",
        "created_at": f"2026-09-{day:02d}T12:00:00Z",
        "updated_at": f"2026-09-{day:02d}T12:00:00Z",
        "run_started_at": f"2026-09-{day:02d}T12:00:00Z",
    }


def github_evidence(evidence_id: str, observation: dict) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "github_state",
        "source": {"provider": "github", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": observation,
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T12:00:00Z",
        "visibility": {
            "completeness": "unknown" if observation.get("access_state") != "AVAILABLE" else "complete",
            "permission_limited": observation.get("access_state") == "UNKNOWN_PERMISSION",
            "retention_limited": False,
        },
        "redactions": [],
    }


def git_evidence(evidence_id: str, subject: dict, observation: dict) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": evidence_id,
        "kind": "git_state",
        "source": {"provider": "git", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": subject,
        "observation": observation,
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T12:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def workflow_source(text: str) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_workflow",
        "kind": "source",
        "source": {"provider": "filesystem", "mechanism": "fixture", "collector": "fixture/v1"},
        "subject": {"type": "github_workflow", "identifier": ".github/workflows/ci.yml"},
        "observation": {"path": ".github/workflows/ci.yml", "text": text, "actionlint_state": "PASS"},
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T12:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def test_healthy_ci_produces_no_material_operational_finding() -> None:
    evidence = history_evidence([run(i, "success") for i in range(1, 11)])
    results = evaluate_ci_operational([evidence], required_workflow_ids={"10"}, now=NOW)

    findings = canonicalize(results, [evidence])

    assert findings == []


def test_chronic_required_ci_materializes_unreliable_gate_and_chronic_failure() -> None:
    runs = [run(i, "failure" if i <= 8 else "success") for i in range(1, 11)]
    evidence = history_evidence(runs)
    results = evaluate_ci_operational([evidence], required_workflow_ids={"10"}, now=NOW)

    findings = canonicalize(results, [evidence])

    assert {item["type"] for item in findings} == {"CHRONIC_FAILURE", "UNRELIABLE_GATE"}


def test_flaky_ci_materializes_flaky_job() -> None:
    same_sha = "b" * 40
    evidence = history_evidence([
        run(2, "failure", sha=same_sha, attempt=1),
        run(1, "success", sha=same_sha, attempt=2),
    ])
    results = evaluate_ci_operational([evidence], required_workflow_ids=set(), now=NOW)

    findings = canonicalize(results, [evidence])

    assert [item["type"] for item in findings] == ["FLAKY_JOB"]


def test_obsolete_required_check_materializes_stale_required_check() -> None:
    repo = github_evidence("ev_github_repository", {"access_state": "AVAILABLE", "delete_branch_on_merge": True})
    branch = github_evidence("ev_github_default_branch", {
        "access_state": "AVAILABLE", "name": "main", "protected": True,
        "required_status_checks": ["test", "old-check"],
    })
    rulesets = github_evidence("ev_github_rulesets", {"access_state": "AVAILABLE", "rulesets": []})
    checks = github_evidence("ev_github_checks", {"access_state": "AVAILABLE", "check_names": ["test"]})
    evidence = [repo, branch, rulesets, checks]

    findings = canonicalize(evaluate_governance(evidence), evidence)

    assert [item["type"] for item in findings] == ["STALE_REQUIRED_CHECK"]


def test_stale_integrated_branch_materializes_cleanup_observation() -> None:
    branch = git_evidence(
        "ev_branch_old",
        {"type": "local_branch", "identifier": "feature-old"},
        {
            "name": "feature-old", "upstream": "origin/feature-old", "upstream_gone": False,
            "last_commit_at": "2025-01-01T00:00:00+00:00", "ahead_of_target": 0,
            "behind_target": 5, "integration_state": "FULLY_INTEGRATED", "target_ref": "main",
        },
    )

    findings = canonicalize(
        evaluate_hygiene([branch], default_branch="main", now=NOW),
        [branch],
    )

    assert len(findings) == 1
    assert findings[0]["type"] == "CLEANUP_CANDIDATE"
    assert findings[0]["output_class"] == "OBSERVATION"


def test_local_only_work_materializes_preservation_risk() -> None:
    branch = git_evidence(
        "ev_branch_local",
        {"type": "local_branch", "identifier": "experiment"},
        {
            "name": "experiment", "upstream": None, "upstream_gone": False,
            "last_commit_at": "2026-09-01T00:00:00+00:00", "ahead_of_target": 3,
            "behind_target": 0, "integration_state": "HAS_UNIQUE_WORK", "target_ref": "main",
        },
    )
    evidence = [branch]

    findings = canonicalize(evaluate_hygiene(evidence, default_branch="main", now=NOW), evidence)

    assert any(item["type"] == "PRESERVATION_RISK" for item in findings)


def test_dirty_orphan_worktree_materializes_preservation_risk() -> None:
    worktree = git_evidence(
        "ev_worktree_dirty",
        {"type": "worktree", "identifier": "/tmp/worktree"},
        {
            "path": "/tmp/worktree", "head_sha": "b" * 40, "branch": "feature-gone",
            "detached": False, "locked": None, "prunable": None,
            "dirty": True, "staged": 0, "unstaged": 1, "untracked": 2,
        },
    )
    findings = canonicalize(evaluate_hygiene([worktree], default_branch="main", now=NOW), [worktree])

    assert any(item["type"] == "PRESERVATION_RISK" for item in findings)
    assert not any(item["type"] == "CLEANUP_CANDIDATE" for item in findings)


def test_permission_limited_github_never_materializes_clean_governance_claim() -> None:
    repo = github_evidence("ev_github_repository", {"access_state": "AVAILABLE", "delete_branch_on_merge": True})
    denied = github_evidence("ev_github_rulesets", {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"})
    branch = github_evidence("ev_github_default_branch", {"access_state": "AVAILABLE", "name": "main", "protected": False, "required_status_checks": []})

    results = evaluate_governance([repo, branch, denied])

    assert next(item for item in results if item["control_id"] == "GH-GOV-001")["state"] == "UNKNOWN_PERMISSION"
    assert canonicalize(results, [repo, branch, denied]) == []


def test_retiring_runner_materializes_deprecation_risk() -> None:
    source = workflow_source("name: CI\npermissions: read-all\njobs:\n  test:\n    runs-on: macos-14\n")
    baseline = {
        "schema_version": "baseline-evidence/v1",
        "subject": "github-actions/macos-14",
        "claim": "runner lifecycle",
        "status": "retiring",
        "effective_dates": {"retirement": "2026-11-02"},
        "source": {"authority": "official", "publisher": "GitHub"},
        "checked_at": "2026-10-02T10:00:00Z",
    }
    results = evaluate_ci_static([source], baseline_evidence=[baseline])

    findings = canonicalize(results, [source])

    assert [item["type"] for item in findings] == ["DEPRECATION_RISK"]
