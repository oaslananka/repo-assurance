from __future__ import annotations

from repo_assurance.evaluators.cicd_static import (
    build_runner_baseline_requests,
    evaluate_ci_static,
    inspect_workflow_source,
)


def workflow_evidence(path: str, text: str, *, actionlint_state: str = "UNAVAILABLE") -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": f"ev_workflow_{path.replace('/', '_')}",
        "kind": "source",
        "source": {"provider": "filesystem", "mechanism": "read", "collector": "workflow-source/v1"},
        "subject": {"type": "github_workflow", "identifier": path},
        "observation": {
            "path": path,
            "text": text,
            "actionlint_state": actionlint_state,
        },
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-02T00:00:00Z",
        "visibility": {"completeness": "complete", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def result(results: list[dict], control_id: str) -> dict:
    return next(item for item in results if item["control_id"] == control_id)


def test_workflow_validity_uses_actionlint_evidence_instead_of_guessing() -> None:
    evidence = workflow_evidence(".github/workflows/ci.yml", "name: CI\n", actionlint_state="PASS")

    results = evaluate_ci_static([evidence])

    assert result(results, "CI-STATIC-001")["state"] == "PASS"


def test_workflow_validity_is_inconclusive_without_specialist_validation() -> None:
    evidence = workflow_evidence(".github/workflows/ci.yml", "name: CI\n")

    results = evaluate_ci_static([evidence])

    item = result(results, "CI-STATIC-001")
    assert item["state"] == "INCONCLUSIVE"
    assert item["reason"] == "actionlint_evidence_unavailable"


def test_write_all_permissions_are_a_finding() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        "name: CI\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    )

    results = evaluate_ci_static([evidence])

    item = result(results, "CI-STATIC-003")
    assert item["state"] == "FINDING"
    assert item["reason"] == "workflow_permissions:write-all"


def test_missing_permissions_are_inconclusive_not_implicitly_safe() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        "name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    )

    results = evaluate_ci_static([evidence])

    item = result(results, "CI-STATIC-003")
    assert item["state"] == "INCONCLUSIVE"
    assert item["reason"] == "workflow_permissions_not_explicit"


def test_action_refs_classify_sha_tag_branch_local_and_docker() -> None:
    sha = "b" * 40
    analysis = inspect_workflow_source(
        ".github/workflows/ci.yml",
        f"""name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: third/secure@{sha}
      - uses: actions/checkout@v4
      - uses: third/custom@main
      - uses: ./local-action
      - uses: docker://alpine:3.20
""",
    )

    assert [(item["uses"], item["ref_kind"]) for item in analysis["actions"]] == [
        (f"third/secure@{sha}", "full_sha"),
        ("actions/checkout@v4", "tag"),
        ("third/custom@main", "branch"),
        ("./local-action", "local"),
        ("docker://alpine:3.20", "docker"),
    ]


def test_mutable_third_party_action_ref_is_finding() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        """name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: third/custom@main
      - uses: actions/checkout@v4
""",
    )

    results = evaluate_ci_static([evidence])

    item = result(results, "CI-STATIC-004")
    assert item["state"] == "FINDING"
    assert item["reason"] == "mutable_third_party_action_refs:third/custom@main"


def test_false_green_patterns_are_detected_without_treating_all_shell_as_bad() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        """name: CI
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
      - run: npm test || true
      - name: advisory
        continue-on-error: true
        run: semgrep scan
""",
    )

    results = evaluate_ci_static([evidence])

    item = result(results, "CI-STATIC-006")
    assert item["state"] == "FINDING"
    assert "continue-on-error:true" in item["reason"]
    assert "shell-error-masking" in item["reason"]


def test_runner_baseline_request_is_generated_for_each_unique_runner() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        """name: CI
jobs:
  linux:
    runs-on: ubuntu-latest
  mac:
    runs-on: macos-14
  duplicate:
    runs-on: ubuntu-latest
""",
    )

    requests = build_runner_baseline_requests([evidence])

    assert requests == [
        {
            "type": "baseline_request",
            "subject": "github-actions/macos-14",
            "identifier": "macos-14",
            "claim": "runner lifecycle",
            "required_authority": "official",
            "reason": "runner lifecycle is time-sensitive",
        },
        {
            "type": "baseline_request",
            "subject": "github-actions/ubuntu-latest",
            "identifier": "ubuntu-latest",
            "claim": "runner lifecycle",
            "required_authority": "official",
            "reason": "runner lifecycle is time-sensitive",
        },
    ]


def test_retiring_runner_baseline_is_finding() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        "name: CI\njobs:\n  test:\n    runs-on: macos-14\n",
    )
    baseline = {
        "schema_version": "baseline-evidence/v1",
        "subject": "github-actions/macos-14",
        "claim": "runner lifecycle",
        "status": "retiring",
        "source": {"authority": "official", "publisher": "GitHub"},
        "checked_at": "2026-10-02T00:00:00Z",
    }

    results = evaluate_ci_static([evidence], baseline_evidence=[baseline])

    item = result(results, "CI-STATIC-008")
    assert item["state"] == "FINDING"
    assert item["reason"] == "runner_lifecycle_risk:macos-14=retiring"


def test_missing_runner_baseline_is_inconclusive() -> None:
    evidence = workflow_evidence(
        ".github/workflows/ci.yml",
        "name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    )

    results = evaluate_ci_static([evidence], baseline_evidence=[])

    item = result(results, "CI-STATIC-008")
    assert item["state"] == "INCONCLUSIVE"
    assert item["reason"] == "current_runner_baseline_missing:ubuntu-latest"


def actionlint_evidence(state: str) -> dict:
    return {
        "schema_version": "evidence/v1",
        "id": "ev_actionlint_ci",
        "kind": "execution",
        "source": {"provider": "actionlint", "mechanism": "stdin", "collector": "actionlint/v1"},
        "subject": {"type": "github_workflow", "identifier": ".github/workflows/ci.yml"},
        "observation": {"actionlint_state": state, "tool_version": "1.7.12", "diagnostics": []},
        "snapshot": {"repository": "acme/demo", "target_commit_sha": "a" * 40},
        "collected_at": "2026-10-03T00:00:00Z",
        "visibility": {"completeness": "complete" if state in {"PASS", "FINDING"} else "unknown", "permission_limited": False, "retention_limited": False},
        "redactions": [],
    }


def test_first_class_actionlint_pass_drives_ci_static_001() -> None:
    source = workflow_evidence(".github/workflows/ci.yml", "name: CI\non: push\njobs: {}\n")
    item = result(evaluate_ci_static([source], specialist_evidence=[actionlint_evidence("PASS")]), "CI-STATIC-001")
    assert item["state"] == "PASS"
    assert item["evidence_ids"] == [
        "ev_actionlint_ci",
        "ev_workflow_.github_workflows_ci.yml",
    ]


def test_first_class_actionlint_finding_drives_ci_static_001() -> None:
    source = workflow_evidence(".github/workflows/ci.yml", "name: CI\njobs: {}\n")
    item = result(evaluate_ci_static([source], specialist_evidence=[actionlint_evidence("FINDING")]), "CI-STATIC-001")
    assert item["state"] == "FINDING"
    assert item["reason"] == "actionlint_validation_failed"


def test_first_class_actionlint_unavailable_is_not_pass() -> None:
    source = workflow_evidence(".github/workflows/ci.yml", "name: CI\non: push\njobs: {}\n")
    item = result(evaluate_ci_static([source], specialist_evidence=[actionlint_evidence("UNAVAILABLE")]), "CI-STATIC-001")
    assert item["state"] == "UNAVAILABLE"


def test_first_class_actionlint_unknown_error_propagates() -> None:
    source = workflow_evidence(
        ".github/workflows/ci.yml",
        "name: CI\non: push\njobs: {}\n",
    )
    item = result(
        evaluate_ci_static(
            [source],
            specialist_evidence=[actionlint_evidence("UNKNOWN_ERROR")],
        ),
        "CI-STATIC-001",
    )
    assert item["state"] == "UNKNOWN_ERROR"
    assert item["reason"] == "actionlint_execution_error"
