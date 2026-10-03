from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_plugin", ROOT / "scripts" / "build_plugin.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_plugin_archive_contains_one_self_contained_plugin(tmp_path: Path) -> None:
    archive_path = MODULE.build_archive(tmp_path / "repo-assurance-plugin.zip")

    with zipfile.ZipFile(archive_path) as archive:
        names = sorted(archive.namelist())
        assert names
        assert all(name.startswith("repo-assurance/") for name in names)
        assert "repo-assurance/plugin.json" in names
        assert "repo-assurance/mcp.json" in names
        assert "repo-assurance/skills/repository-assurance/SKILL.md" in names
        assert "repo-assurance/src/repo_assurance/mcp_server.py" in names
        assert not any("/tests/" in name for name in names)
        manifest = json.loads(archive.read("repo-assurance/plugin.json"))
        assert manifest["name"] == "repo-assurance"


def test_plugin_archive_is_deterministic(tmp_path: Path) -> None:
    first = MODULE.build_archive(tmp_path / "first.zip")
    second = MODULE.build_archive(tmp_path / "second.zip")

    assert first.read_bytes() == second.read_bytes()
