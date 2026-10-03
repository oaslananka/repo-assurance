from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_skill",
    ROOT / "scripts" / "build_skill.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_skill_archive_has_canonical_layout(tmp_path: Path) -> None:
    archive_path = MODULE.build_archive(tmp_path / "skill.zip")

    with zipfile.ZipFile(archive_path) as archive:
        assert archive.namelist() == ["repository-assurance/SKILL.md"]
        assert archive.read("repository-assurance/SKILL.md") == (
            ROOT / "skills" / "repository-assurance" / "SKILL.md"
        ).read_bytes()


def test_skill_archive_is_deterministic(tmp_path: Path) -> None:
    first = MODULE.build_archive(tmp_path / "first.zip")
    second = MODULE.build_archive(tmp_path / "second.zip")

    assert first.read_bytes() == second.read_bytes()
