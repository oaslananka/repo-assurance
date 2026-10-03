from __future__ import annotations

import subprocess

import pytest

from repo_assurance.security.mutation_guard import (
    MutationBlockedError,
    ReadOnlyCommandRunner,
)


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "push"],
        ["git", "branch", "-D", "old"],
        ["git", "reset", "--hard", "HEAD~1"],
        ["git", "clean", "-fd"],
        ["git", "stash", "drop"],
        ["git", "checkout", "main"],
        ["git", "fetch", "origin"],
        ["gh", "pr", "merge", "12"],
        ["gh", "issue", "close", "12"],
        ["gh", "api", "--method", "POST", "/repos/o/r/issues"],
        ["gh", "api", "-X", "DELETE", "/repos/o/r/git/refs/heads/old"],
    ],
)
def test_mutating_commands_are_blocked(argv: list[str]) -> None:
    runner = ReadOnlyCommandRunner(executor=lambda *args, **kwargs: None)

    with pytest.raises(MutationBlockedError):
        runner.run(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "status", "--porcelain=v2"],
        ["git", "rev-parse", "HEAD"],
        ["git", "branch", "--format=%(refname:short)"],
        ["git", "worktree", "list", "--porcelain"],
        ["git", "stash", "list"],
        ["git", "merge-base", "main", "feature"],
        ["gh", "api", "/repos/o/r"],
        ["gh", "api", "--method", "GET", "/repos/o/r/rulesets"],
        ["gh", "run", "list", "--json", "databaseId,conclusion"],
        ["gh", "repo", "view", "o/r", "--json", "nameWithOwner"],
        ["gh", "pr", "list", "--json", "number,state"],
    ],
)
def test_read_only_commands_are_allowed(argv: list[str]) -> None:
    calls: list[list[str]] = []

    def fake_executor(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    runner = ReadOnlyCommandRunner(executor=fake_executor)

    result = runner.run(argv)

    assert result.returncode == 0
    assert calls == [argv]


def test_unknown_command_family_is_blocked_by_default() -> None:
    runner = ReadOnlyCommandRunner(executor=lambda *args, **kwargs: None)

    with pytest.raises(MutationBlockedError):
        runner.run(["curl", "https://example.com"])


def test_blocked_command_is_never_executed() -> None:
    called = False

    def fake_executor(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    runner = ReadOnlyCommandRunner(executor=fake_executor)

    with pytest.raises(MutationBlockedError):
        runner.run(["git", "push"])

    assert called is False


def test_git_rev_list_is_allowed_for_read_only_reachability_analysis() -> None:
    calls: list[list[str]] = []

    def fake_executor(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "1\n", "")

    runner = ReadOnlyCommandRunner(executor=fake_executor)
    result = runner.run(["git", "rev-list", "--count", "main..feature"])

    assert result.returncode == 0
    assert calls == [["git", "rev-list", "--count", "main..feature"]]


def test_missing_allowlisted_executable_returns_127_instead_of_crashing() -> None:
    def missing_executor(command, **kwargs):
        raise FileNotFoundError("gh not installed")

    runner = ReadOnlyCommandRunner(executor=missing_executor)
    result = runner.run(["gh", "api", "/repos/acme/demo"])

    assert result.returncode == 127
    assert "gh not installed" in result.stderr


def test_actionlint_stdin_mode_is_allowlisted() -> None:
    calls = []
    def fake_executor(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        return subprocess.CompletedProcess(["actionlint"], 0, "[]", "")
    runner = ReadOnlyCommandRunner(executor=fake_executor)
    argv = ["actionlint", "-no-color", "-shellcheck=", "-pyflakes=", "-format", "{{json .}}", "-stdin-filename", ".github/workflows/ci.yml", "-"]
    result = runner.run(argv, stdin_text="name: CI\n")
    assert result.returncode == 0
    assert calls == [(argv, "name: CI\n")]


@pytest.mark.parametrize("argv", [
    ["actionlint", "-init-config"],
    ["actionlint", ".github/workflows/ci.yml"],
    ["actionlint", "-no-color", "-shellcheck=shellcheck", "-pyflakes=", "-format", "{{json .}}", "-stdin-filename", ".github/workflows/ci.yml", "-"],
])
def test_actionlint_mutating_or_nondeterministic_modes_are_blocked(argv: list[str]) -> None:
    runner = ReadOnlyCommandRunner(executor=lambda *args, **kwargs: None)
    with pytest.raises(MutationBlockedError):
        runner.run(argv)
