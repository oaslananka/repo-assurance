from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import tarfile
# subprocess is limited to validated internal release command vectors.
import subprocess  # nosec B404
import tomllib
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class ReleaseError(RuntimeError):
    pass


def release_identity(root: Path) -> dict[str, str]:
    package = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    plugin = json.loads((root / "plugin.json").read_text(encoding="utf-8"))

    project = package.get("project", {})
    name = str(project.get("name", "")).strip()
    version = str(project.get("version", "")).strip()
    plugin_version = str(plugin.get("version", "")).strip()

    if not name:
        raise ReleaseError("project name is missing from pyproject.toml")
    if not SEMVER.fullmatch(version):
        raise ReleaseError(f"project version is not valid Semantic Versioning: {version!r}")
    if plugin_version != version:
        raise ReleaseError(
            f"package/plugin version mismatch: package={version!r} plugin={plugin_version!r}"
        )

    return {
        "name": name,
        "version": version,
        "tag": f"v{version}",
    }


def git_commit(root: Path) -> str:
    result = subprocess.run(  # nosec B603 B607
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("unable to resolve exact Git commit")
    return commit


def assert_clean_worktree(root: Path) -> None:
    result = subprocess.run(  # nosec B603 B607
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise ReleaseError("unable to inspect Git worktree state")
    if result.stdout.strip():
        raise ReleaseError("release build requires a clean Git worktree")


def assert_expected_tag(root: Path, *, expected_tag: str, tag: str) -> None:
    if expected_tag != tag:
        raise ReleaseError(
            f"expected tag {expected_tag!r} does not match canonical release tag {tag!r}"
        )

    result = subprocess.run(  # nosec B603 B607
        ["git", "tag", "--points-at", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise ReleaseError("unable to inspect tags pointing at HEAD")
    tags = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    if expected_tag not in tags:
        raise ReleaseError(
            f"release build requires {expected_tag!r} to point at the exact HEAD commit"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_archive_member(name: str) -> bool:
    member = Path(name)
    return bool(name) and not member.is_absolute() and ".." not in member.parts


def _normalize_sdist(path: Path, *, source_date_epoch: int) -> None:
    """Rewrite a Python sdist with deterministic tar and gzip metadata."""
    try:
        with tarfile.open(path, mode="r:gz") as source:
            members = source.getmembers()
            for member in members:
                if not _safe_archive_member(member.name):
                    raise ReleaseError(
                        f"unsafe sdist member path: {member.name!r}"
                    )

            canonical_tar = io.BytesIO()
            with tarfile.open(
                fileobj=canonical_tar,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as target:
                for member in sorted(members, key=lambda item: item.name):
                    normalized = copy.copy(member)
                    normalized.uid = 0
                    normalized.gid = 0
                    normalized.uname = ""
                    normalized.gname = ""
                    normalized.mtime = source_date_epoch
                    normalized.pax_headers = {}

                    if normalized.isdir():
                        normalized.mode = 0o755
                    elif normalized.isfile():
                        normalized.mode = (
                            0o755 if member.mode & 0o111 else 0o644
                        )

                    payload = (
                        source.extractfile(member)
                        if member.isfile()
                        else None
                    )
                    target.addfile(normalized, payload)
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseError(f"unable to normalize sdist {path.name}: {exc}") from exc

    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as raw, gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            compresslevel=9,
            mtime=source_date_epoch,
        ) as compressed:
            compressed.write(canonical_tar.getvalue())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def build_manifest(
    *,
    version: str,
    git_commit: str,
    tag: str,
    artifacts: Sequence[Path],
) -> dict[str, Any]:
    return {
        "schema_version": "release-manifest/v1",
        "name": "repo-assurance",
        "version": version,
        "tag": tag,
        "git_commit": git_commit,
        "artifacts": [
            {
                "name": path.name,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
            for path in sorted(artifacts, key=lambda item: item.name)
        ],
    }


def assert_safe_output_path(root: Path, output: Path) -> Path:
    root = root.resolve()
    output = output.resolve()
    dist_root = (root / "dist").resolve()

    if output == root or output in root.parents:
        raise ReleaseError(
            "release output must not be the repository root or a parent of it"
        )

    if root in output.parents and not (
        output == dist_root or dist_root in output.parents
    ):
        raise ReleaseError(
            "release output inside the repository must be under dist/"
        )

    return output


def _source_date_epoch(root: Path) -> str:
    result = subprocess.run(  # nosec B603 B607
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdigit():
        raise ReleaseError("unable to resolve commit timestamp")
    return value


def _build_python_distributions(
    root: Path,
    output: Path,
    *,
    source_date_epoch: int,
) -> list[Path]:
    try:
        from build import ProjectBuilder
    except ImportError as exc:
        raise ReleaseError(
            "release build requires the 'build' package"
        ) from exc

    previous_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    try:
        builder = ProjectBuilder(str(root))
        built = [
            Path(builder.build(distribution, str(output)))
            for distribution in ("sdist", "wheel")
        ]
    except Exception as exc:
        raise ReleaseError(f"python distribution build failed: {exc}") from exc
    finally:
        if previous_epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous_epoch

    return built


def _load_builder_module(path: Path, *, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ReleaseError(f"unable to load release builder: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_plugin_archive(root: Path, output: Path) -> None:
    module = _load_builder_module(
        root / "scripts" / "build_plugin.py",
        module_name="_repo_assurance_release_plugin_builder",
    )
    try:
        module.build_archive(output)
    except Exception as exc:
        raise ReleaseError(f"plugin build failed: {exc}") from exc


def _build_skill_archive(root: Path, output: Path) -> None:
    module = _load_builder_module(
        root / "scripts" / "build_skill.py",
        module_name="_repo_assurance_release_skill_builder",
    )
    try:
        module.build_archive(output)
    except Exception as exc:
        raise ReleaseError(f"skill build failed: {exc}") from exc


def build_release(
    root: Path,
    *,
    expected_tag: str,
    output: Path,
) -> Path:
    root = root.resolve()
    identity = release_identity(root)
    assert_clean_worktree(root)
    assert_expected_tag(root, expected_tag=expected_tag, tag=identity["tag"])
    commit = git_commit(root)

    output = assert_safe_output_path(root, output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    version = identity["version"]
    source_date_epoch = int(_source_date_epoch(root))

    python_artifacts = _build_python_distributions(
        root,
        output,
        source_date_epoch=source_date_epoch,
    )
    python_sdists = sorted(
        path
        for path in python_artifacts
        if path.name.endswith(".tar.gz")
    )
    for sdist in python_sdists:
        _normalize_sdist(
            sdist,
            source_date_epoch=source_date_epoch,
        )

    plugin = output / f"repo-assurance-plugin-{version}.zip"
    _build_plugin_archive(root, plugin)

    skill = output / f"repository-assurance-skill-{version}.zip"
    _build_skill_archive(root, skill)

    source = output / f"repo-assurance-source-{version}.tar.gz"
    archive_result = subprocess.run(  # nosec B603 B607
        [
            "git",
            "archive",
            "--format=tar.gz",
            f"--prefix=repo-assurance-{version}/",
            f"--output={source}",
            "HEAD",
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    _assert_success(archive_result, label="source archive build")

    python_artifacts = sorted(
        python_artifacts,
        key=lambda path: path.name,
    )
    artifacts = [*python_artifacts, plugin, skill, source]
    manifest = build_manifest(
        version=version,
        git_commit=commit,
        tag=identity["tag"],
        artifacts=artifacts,
    )
    manifest_path = output / "release-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    sums = output / "SHA256SUMS"
    sums.write_text(
        "".join(
            f"{item['sha256']}  {item['name']}\n"
            for item in manifest["artifacts"]
        ),
        encoding="utf-8",
    )
    return output


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a validated, non-publishing Repo Assurance release artifact set "
            "from an exact tagged commit."
        )
    )
    parser.add_argument(
        "--expected-tag",
        required=True,
        help="Exact release tag expected to point at HEAD (for example v0.1.1).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "release",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    output = build_release(
        ROOT,
        expected_tag=args.expected_tag,
        output=args.output,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
