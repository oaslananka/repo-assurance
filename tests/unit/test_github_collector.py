from __future__ import annotations

import json
import subprocess

from repo_assurance.collectors.github import (
    GitHubAccessState,
    classify_gh_error,
    collect_repository_state,
    collect_rulesets,
)


class FakeRunner:
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.result


def cp(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["gh"], returncode, stdout, stderr)


def test_classify_permission_error() -> None:
    assert classify_gh_error(cp(1, stderr="gh: Resource not accessible (HTTP 403)")) is GitHubAccessState.UNKNOWN_PERMISSION


def test_classify_auth_error() -> None:
    assert classify_gh_error(cp(1, stderr="gh: Bad credentials (HTTP 401)")) is GitHubAccessState.AUTH_FAILED


def test_classify_server_error() -> None:
    assert classify_gh_error(cp(1, stderr="gh: Internal Server Error (HTTP 500)")) is GitHubAccessState.UNKNOWN_ERROR


def test_collect_repository_state_normalizes_json() -> None:
    payload = {
        "full_name": "acme/demo",
        "default_branch": "main",
        "private": False,
        "archived": False,
        "fork": False,
        "delete_branch_on_merge": True,
        "allow_merge_commit": True,
        "allow_rebase_merge": False,
        "allow_squash_merge": True,
    }
    runner = FakeRunner(cp(0, stdout=json.dumps(payload)))
    evidence = collect_repository_state("acme/demo", "a" * 40, runner=runner)
    assert runner.calls == [["gh", "api", "/repos/acme/demo"]]
    assert evidence[0]["observation"]["access_state"] == "AVAILABLE"
    assert evidence[0]["observation"]["default_branch"] == "main"
    assert evidence[0]["observation"]["delete_branch_on_merge"] is True
    assert evidence[0]["visibility"]["completeness"] == "complete"


def test_collect_rulesets_normalizes_ruleset_list() -> None:
    runner = FakeRunner(cp(0, stdout=json.dumps([
        {"id": 1, "name": "main", "enforcement": "active", "target": "branch"},
        {"id": 2, "name": "audit", "enforcement": "disabled", "target": "branch"},
    ])))
    evidence = collect_rulesets("acme/demo", "a" * 40, runner=runner)
    assert runner.calls == [["gh", "api", "/repos/acme/demo/rulesets?includes_parents=true"]]
    assert evidence[0]["observation"]["access_state"] == "AVAILABLE"
    assert [item["name"] for item in evidence[0]["observation"]["rulesets"]] == ["main", "audit"]


def test_permission_denied_becomes_explicit_evidence_gap_not_empty_success() -> None:
    runner = FakeRunner(cp(1, stderr="gh: Resource not accessible by integration (HTTP 403)"))
    evidence = collect_rulesets("acme/demo", "a" * 40, runner=runner)
    item = evidence[0]
    assert item["observation"] == {"access_state": "UNKNOWN_PERMISSION", "error_code": "HTTP_403"}
    assert item["visibility"] == {
        "completeness": "unknown",
        "permission_limited": True,
        "retention_limited": False,
    }


def test_invalid_auth_is_distinct_from_permission_denied() -> None:
    runner = FakeRunner(cp(1, stderr="gh: Bad credentials (HTTP 401)"))
    evidence = collect_repository_state("acme/demo", "a" * 40, runner=runner)
    assert evidence[0]["observation"]["access_state"] == "AUTH_FAILED"
    assert evidence[0]["observation"]["error_code"] == "HTTP_401"


def test_malformed_success_json_becomes_unknown_error() -> None:
    runner = FakeRunner(cp(0, stdout="not-json"))
    evidence = collect_repository_state("acme/demo", "a" * 40, runner=runner)
    assert evidence[0]["observation"] == {
        "access_state": "UNKNOWN_ERROR",
        "error_code": "MALFORMED_JSON",
    }
    assert evidence[0]["visibility"]["completeness"] == "unknown"
