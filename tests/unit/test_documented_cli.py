from __future__ import annotations

from pathlib import Path

import pytest

from repo_assurance.cli import build_parser


ROOT = Path(__file__).resolve().parents[2]


def test_readme_documents_existing_cli_commands() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    parser = build_parser()
    subcommands = parser._subparsers._group_actions[0].choices
    for command in ("discover", "plan", "audit", "validate", "render"):
        assert command in subcommands
        assert f"repo-assurance {command}" in text


@pytest.mark.parametrize(
    "path",
    [
        "references/audit-protocol.md",
        "references/evidence-model.md",
        "references/finding-model.md",
        "references/control-authoring.md",
    ],
)
def test_reference_documents_exist(path: str) -> None:
    assert (ROOT / path).is_file()
