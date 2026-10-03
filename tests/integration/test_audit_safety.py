from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repo_assurance.cli import main
from repo_assurance.security.mutation_guard import ReadOnlyCommandRunner

FAKE_PAT = "ghp_" + "S" * 36


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def init_repo(tmp_path: Path, *, with_secret: bool = False) -> Path:
    repo = tmp_path / "demo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    secret_line = f"      - run: echo {FAKE_PAT}\n" if with_secret else ""
    (workflow_dir / "ci.yml").write_text(
        "name: CI\npermissions: read-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        + secret_line
        + "      - run: python app.py\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    git(repo, "remote", "add", "origin", "https://github.com/acme/demo.git")
    git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "HEAD"))
    return repo


def test_full_audit_attempts_only_read_only_external_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = init_repo(tmp_path)
    before_head = git(repo, "rev-parse", "HEAD")
    before_status = git(repo, "status", "--porcelain=v1")
    before_refs = git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
    attempted: list[list[str]] = []
    original = ReadOnlyCommandRunner.run

    def recording_run(self, argv, *, cwd=None, stdin_text=None):
        attempted.append(list(argv))
        return original(self, argv, cwd=cwd, stdin_text=stdin_text)

    monkeypatch.setattr(ReadOnlyCommandRunner, "run", recording_run)
    output = tmp_path / "audit-output"

    assert main(["audit", "--repo", str(repo), "--offline", "--output", str(output)]) == 0
    capsys.readouterr()

    forbidden = {
        ("git", "push"),
        ("git", "reset"),
        ("git", "clean"),
        ("git", "checkout"),
        ("git", "switch"),
        ("git", "fetch"),
        ("git", "pull"),
        ("gh", "pr", "merge"),
        ("gh", "issue", "close"),
    }
    assert attempted
    for command in attempted:
        assert tuple(command[: len(next(iter(forbidden)))]) not in forbidden
        if command[:2] == ["gh", "api"]:
            lowered = [part.lower() for part in command]
            assert "post" not in lowered
            assert "patch" not in lowered
            assert "delete" not in lowered

    assert git(repo, "rev-parse", "HEAD") == before_head
    assert git(repo, "status", "--porcelain=v1") == before_status
    assert git(repo, "for-each-ref", "--format=%(refname) %(objectname)") == before_refs


def test_secret_shaped_values_never_reach_generated_artifacts_or_stdout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = init_repo(tmp_path, with_secret=True)
    output = tmp_path / "audit-output"

    assert main([
        "audit", "--repo", str(repo), "--offline", "--debug-evidence",
        "--output", str(output),
    ]) == 0
    stdout = capsys.readouterr().out

    artifacts = [
        output / "audit-plan.json",
        output / "audit-report.json",
        output / "audit-report.md",
        output / "evidence.json",
    ]
    assert all(path.is_file() for path in artifacts)
    assert FAKE_PAT not in stdout
    for path in artifacts:
        assert FAKE_PAT not in path.read_text(encoding="utf-8")

    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    workflow = next(item for item in evidence if item["source"]["collector"] == "workflow-source/v1")
    assert "[REDACTED]" in workflow["observation"]["text"]
    assert workflow["redactions"]
