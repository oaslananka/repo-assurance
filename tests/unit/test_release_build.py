from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_release", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_identity_matches_current_repository() -> None:
    module = load_module()

    identity = module.release_identity(ROOT)

    assert identity["name"] == "repo-assurance"
    assert identity["version"] == "0.2.1"
    assert identity["tag"] == "v0.2.1"


def test_release_identity_rejects_plugin_version_drift(tmp_path: Path) -> None:
    module = load_module()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="repo-assurance"\nversion="1.2.3"\n',
        encoding="utf-8",
    )
    (tmp_path / "plugin.json").write_text(
        json.dumps({"name": "repo-assurance", "version": "1.2.4"}),
        encoding="utf-8",
    )

    with pytest.raises(module.ReleaseError, match="version mismatch"):
        module.release_identity(tmp_path)


def test_manifest_records_exact_commit_and_artifact_hashes(tmp_path: Path) -> None:
    module = load_module()
    artifact = tmp_path / "repo-assurance-plugin-0.1.1.zip"
    artifact.write_bytes(b"plugin-bytes")

    manifest = module.build_manifest(
        version="0.1.1",
        git_commit="a" * 40,
        tag="v0.1.1",
        artifacts=[artifact],
    )

    assert manifest["schema_version"] == "release-manifest/v1"
    assert manifest["version"] == "0.1.1"
    assert manifest["git_commit"] == "a" * 40
    assert manifest["tag"] == "v0.1.1"
    assert manifest["artifacts"][0]["name"] == artifact.name
    assert len(manifest["artifacts"][0]["sha256"]) == 64


def _init_git_repo(path: Path) -> None:
    path.mkdir()
    (path / "file.txt").write_text("initial\n", encoding="utf-8")
    import subprocess

    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=path, check=True, capture_output=True)


def test_expected_tag_must_match_canonical_tag_and_point_at_head(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    _init_git_repo(repo)

    import subprocess

    subprocess.run(["git", "tag", "v1.2.3"], cwd=repo, check=True)

    module.assert_expected_tag(repo, expected_tag="v1.2.3", tag="v1.2.3")

    with pytest.raises(module.ReleaseError, match="does not match canonical"):
        module.assert_expected_tag(repo, expected_tag="v1.2.4", tag="v1.2.3")

    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "later"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    with pytest.raises(module.ReleaseError, match="point at the exact HEAD"):
        module.assert_expected_tag(repo, expected_tag="v1.2.3", tag="v1.2.3")


def test_release_build_rejects_dirty_worktree(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "file.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(module.ReleaseError, match="clean Git worktree"):
        module.assert_clean_worktree(repo)

def test_release_output_path_rejects_destructive_locations(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(module.ReleaseError, match="repository root or a parent"):
        module.assert_safe_output_path(repo, repo)

    with pytest.raises(module.ReleaseError, match="repository root or a parent"):
        module.assert_safe_output_path(repo, tmp_path)

    with pytest.raises(module.ReleaseError, match="must be under dist"):
        module.assert_safe_output_path(repo, repo / "src" / "release")


def test_release_output_path_allows_dist_or_external_directory(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()

    assert module.assert_safe_output_path(
        repo, repo / "dist" / "release"
    ) == (repo / "dist" / "release").resolve()

    external = tmp_path / "external-release"
    assert module.assert_safe_output_path(repo, external) == external.resolve()

def test_release_builder_has_no_generic_subprocess_wrapper() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "def _run(" not in source
    assert "sys.executable" not in source
    assert "shell=True" not in source
    assert source.count("subprocess.run(") == 5


def test_sdist_normalization_is_deterministic(tmp_path: Path) -> None:
    import gzip
    import io
    import tarfile
    import time

    module = load_module()

    def make_sdist(path: Path, *, mtime: float, uid: int, mode: int) -> None:
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
            root = tarfile.TarInfo("repo_assurance-0.1.1")
            root.type = tarfile.DIRTYPE
            root.mtime = mtime
            root.uid = uid
            root.gid = uid
            root.uname = "builder"
            root.gname = "builder"
            root.mode = 0o700
            archive.addfile(root)

            payload = b"payload\n"
            member = tarfile.TarInfo("repo_assurance-0.1.1/module.py")
            member.size = len(payload)
            member.mtime = mtime
            member.uid = uid
            member.gid = uid
            member.uname = "builder"
            member.gname = "builder"
            member.mode = mode
            archive.addfile(member, io.BytesIO(payload))

        with path.open("wb") as raw:
            with gzip.GzipFile(
                filename=path.name,
                mode="wb",
                fileobj=raw,
                mtime=int(time.time()),
            ) as compressed:
                compressed.write(tar_bytes.getvalue())

    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    make_sdist(first, mtime=1000.25, uid=1000, mode=0o600)
    make_sdist(second, mtime=2000.75, uid=501, mode=0o664)

    epoch = 1_700_000_000
    module._normalize_sdist(first, source_date_epoch=epoch)
    module._normalize_sdist(second, source_date_epoch=epoch)

    assert first.read_bytes() == second.read_bytes()

    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
        assert all(member.mtime == epoch for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert all(member.uname == "" and member.gname == "" for member in members)
        assert all(member.pax_headers == {} for member in members)
        file_member = next(member for member in members if member.isfile())
        assert file_member.mode == 0o644
        assert archive.extractfile(file_member).read() == b"payload\n"


def test_sdist_normalization_rejects_parent_traversal(tmp_path: Path) -> None:
    import gzip
    import io
    import tarfile

    module = load_module()
    path = tmp_path / "unsafe.tar.gz"

    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
        payload = b"bad"
        member = tarfile.TarInfo("../escape")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    path.write_bytes(gzip.compress(tar_bytes.getvalue(), mtime=0))

    with pytest.raises(module.ReleaseError, match="unsafe sdist member path"):
        module._normalize_sdist(path, source_date_epoch=1_700_000_000)
