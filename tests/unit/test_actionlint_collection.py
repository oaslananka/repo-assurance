from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repo_assurance.collectors.actionlint import collect_actionlint_evidence


class FakeRunner:
    def __init__(self, version=None, lint=None):
        self.version = version or cp(0, "1.7.12\n")
        self.lint = list(lint or [])
        self.calls = []

    def run(self, argv, *, cwd=None, stdin_text=None):
        self.calls.append((list(argv), stdin_text, cwd))
        if list(argv) == ["actionlint", "-version"]:
            return self.version
        return self.lint.pop(0)


def cp(code: int, out: str = "", err: str = ""):
    return subprocess.CompletedProcess(["actionlint"], code, out, err)


def repo_with_workflow(tmp_path: Path, text: str) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
    path = repo / ".github/workflows/ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(text)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    return repo, sha


def test_actionlint_pass_and_provenance(tmp_path: Path) -> None:
    repo, sha = repo_with_workflow(tmp_path, "name: CI\non: push\njobs: {}\n")
    runner = FakeRunner(lint=[cp(0, "[]")])

    evidence = collect_actionlint_evidence(repo, repository="acme/demo", target_commit_sha=sha, runner=runner)

    item = evidence[0]
    assert item["kind"] == "execution"
    assert item["source"]["provider"] == "actionlint"
    assert item["source"]["mechanism"] == "stdin"
    assert item["snapshot"]["target_commit_sha"] == sha
    assert item["subject"]["identifier"] == ".github/workflows/ci.yml"
    assert item["observation"]["actionlint_state"] == "PASS"
    assert item["observation"]["tool_version"] == "1.7.12"
    assert item["observation"]["diagnostics"] == []
    assert runner.calls[1][1] == "name: CI\non: push\njobs: {}\n"
    assert runner.calls[1][2] != repo


def test_actionlint_finding_drops_snippet(tmp_path: Path) -> None:
    repo, sha = repo_with_workflow(tmp_path, "name: CI\njobs: {}\n")
    raw = [{
        "message": "\"on\" section is missing in workflow",
        "filepath": ".github/workflows/ci.yml",
        "line": 1,
        "column": 1,
        "end_column": 5,
        "kind": "syntax-check",
        "snippet": "name: CI",
    }]
    runner = FakeRunner(lint=[cp(1, json.dumps(raw))])

    item = collect_actionlint_evidence(repo, repository="acme/demo", target_commit_sha=sha, runner=runner)[0]

    assert item["observation"]["actionlint_state"] == "FINDING"
    diagnostic = item["observation"]["diagnostics"][0]
    assert diagnostic["kind"] == "syntax-check"
    assert "snippet" not in diagnostic


def test_actionlint_missing_is_unavailable(tmp_path: Path) -> None:
    repo, sha = repo_with_workflow(tmp_path, "name: CI\non: push\njobs: {}\n")
    runner = FakeRunner(version=cp(127, "", "not found"))

    item = collect_actionlint_evidence(repo, repository="acme/demo", target_commit_sha=sha, runner=runner)[0]

    assert item["observation"]["actionlint_state"] == "UNAVAILABLE"
    assert item["observation"]["error_code"] == "ACTIONLINT_NOT_FOUND"
    assert len(runner.calls) == 1


def test_actionlint_uses_target_commit_not_checkout(tmp_path: Path) -> None:
    target = "name: TARGET\njobs: {}\n"
    repo, sha = repo_with_workflow(tmp_path, target)
    path = repo / ".github/workflows/ci.yml"
    path.write_text("name: LATER\non: push\njobs: {}\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "later"], cwd=repo, check=True, capture_output=True)
    path.write_text("name: DIRTY\n")
    runner = FakeRunner(lint=[cp(1, "[]")])

    collect_actionlint_evidence(repo, repository="acme/demo", target_commit_sha=sha, runner=runner)

    assert runner.calls[1][1] == target


def test_actionlint_execution_failure_is_unknown_error(tmp_path: Path) -> None:
    repo, sha = repo_with_workflow(tmp_path, "name: CI\non: push\njobs: {}\n")
    runner = FakeRunner(lint=[cp(2, "", "unexpected failure")])

    item = collect_actionlint_evidence(
        repo,
        repository="acme/demo",
        target_commit_sha=sha,
        runner=runner,
    )[0]

    assert item["observation"]["actionlint_state"] == "UNKNOWN_ERROR"
    assert item["observation"]["error_code"] == "ACTIONLINT_EXIT_2"


def test_actionlint_malformed_json_is_unknown_error(tmp_path: Path) -> None:
    repo, sha = repo_with_workflow(tmp_path, "name: CI\non: push\njobs: {}\n")
    runner = FakeRunner(lint=[cp(1, "not-json")])

    item = collect_actionlint_evidence(
        repo,
        repository="acme/demo",
        target_commit_sha=sha,
        runner=runner,
    )[0]

    assert item["observation"]["actionlint_state"] == "UNKNOWN_ERROR"
    assert item["observation"]["error_code"] == "MALFORMED_ACTIONLINT_OUTPUT"
