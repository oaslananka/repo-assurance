from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Sequence


class MutationBlockedError(RuntimeError):
    """Raised when audit mode attempts an operation that can change external state."""


Executor = Callable[..., subprocess.CompletedProcess[str]]


class ReadOnlyCommandRunner:
    """Execute only explicitly recognized read-only Git and GitHub CLI commands."""

    def __init__(self, executor: Executor = subprocess.run) -> None:
        self._executor = executor

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = list(argv)
        self._assert_read_only(command)
        try:
            return self._executor(
                command,
                cwd=cwd,
                text=True,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(command, 127, "", str(exc))

    def _assert_read_only(self, argv: list[str]) -> None:
        if not argv:
            raise MutationBlockedError("empty command is not allowed")
        if argv[0] == "git":
            self._assert_git_read_only(argv[1:])
            return
        if argv[0] == "gh":
            self._assert_gh_read_only(argv[1:])
            return
        raise MutationBlockedError(f"command family is not allowlisted: {argv[0]}")

    def _assert_git_read_only(self, args: list[str]) -> None:
        if not args:
            raise MutationBlockedError("git command is missing a subcommand")
        subcommand = args[0]
        rest = args[1:]

        always_read_only = {
            "status",
            "rev-parse",
            "log",
            "show",
            "diff",
            "merge-base",
            "for-each-ref",
            "ls-files",
            "cat-file",
            "rev-list",
        }
        if subcommand in always_read_only:
            return

        if subcommand == "branch":
            mutation_flags = {
                "-d", "-D", "-m", "-M", "-c", "-C",
                "--delete", "--move", "--copy", "--edit-description",
                "--set-upstream-to", "--unset-upstream",
            }
            if any(arg in mutation_flags or arg.startswith("--set-upstream-to=") for arg in rest):
                raise MutationBlockedError("git branch mutation is blocked")
            if any(not arg.startswith("-") for arg in rest):
                raise MutationBlockedError("git branch positional arguments can create or rename branches")
            return

        if subcommand == "worktree" and rest[:1] == ["list"]:
            return
        if subcommand == "stash" and rest[:1] in (["list"], ["show"]):
            return
        if subcommand == "remote":
            if not rest or rest[0] in {"-v", "--verbose", "get-url", "show"}:
                return
        if subcommand == "config":
            if any(flag in rest for flag in ("--get", "--get-all", "--get-regexp", "--list", "-l")):
                return

        raise MutationBlockedError(f"git subcommand is not allowlisted for audit mode: {subcommand}")

    def _assert_gh_read_only(self, args: list[str]) -> None:
        if not args:
            raise MutationBlockedError("gh command is missing a subcommand")
        subcommand = args[0]
        rest = args[1:]

        if subcommand == "api":
            method = "GET"
            for index, arg in enumerate(rest):
                if arg in {"--method", "-X"}:
                    if index + 1 >= len(rest):
                        raise MutationBlockedError("gh api method flag is missing a value")
                    method = rest[index + 1].upper()
                elif arg.startswith("--method="):
                    method = arg.split("=", 1)[1].upper()
            if method != "GET":
                raise MutationBlockedError(f"gh api mutation method is blocked: {method}")
            if any(arg in {"-f", "--raw-field", "-F", "--field", "--input"} or arg.startswith(("--raw-field=", "--field=", "--input=")) for arg in rest):
                raise MutationBlockedError("gh api request-body options are blocked in audit mode")
            return

        safe_verbs = {
            "repo": {"view"},
            "run": {"list", "view"},
            "workflow": {"list", "view"},
            "pr": {"list", "view", "checks", "status"},
            "issue": {"list", "view", "status"},
            "release": {"list", "view"},
            "auth": {"status"},
            "secret": {"list"},
            "variable": {"list", "get"},
        }
        if subcommand in safe_verbs and rest and rest[0] in safe_verbs[subcommand]:
            return

        raise MutationBlockedError(f"gh subcommand is not allowlisted for audit mode: {' '.join(args[:2])}")
