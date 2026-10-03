from __future__ import annotations

import zipfile
from pathlib import Path

from build import ProjectBuilder


ROOT = Path(__file__).resolve().parents[2]


def test_built_wheel_contains_runtime_catalog_and_schemas(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = Path(ProjectBuilder(str(ROOT)).build("wheel", str(dist)))

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    assert "repo_assurance/resources/controls/snapshot.v1.json" in names
    assert "repo_assurance/resources/schemas/control.v1.schema.json" in names
