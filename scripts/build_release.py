from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
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


def _run(
    argv: Sequence[str],
    *,
    root: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


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
    result = _run(["git", "rev-parse", "HEAD"], root=root)
    commit = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("unable to resolve exact Git commit")
    return commit


def assert_clean_worktree(root: Path) -> None:
    result = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        root=root,
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

    result = _run(["git", "tag", "--points-at", "HEAD"], root=root)
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


def _source_date_epoch(root: Path) -> str:
    result = _run(["git", "show", "-s", "--format=%ct", "HEAD"], root=root)
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdigit():
        raise ReleaseError("unable to resolve commit timestamp")
    return value


def _run_checked(
    argv: Sequence[str],
    *,
    root: Path,
    env: dict[str, str] | None = None,
) -> None:
    result = _run(argv, root=root, env=env)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        raise ReleaseError(f"command failed: {' '.join(argv)}: {detail}")


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

    output = output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    version = identity["version"]
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = _source_date_epoch(root)

    _run_checked(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            str(root),
        ],
        root=root,
        env=env,
    )

    plugin = output / f"repo-assurance-plugin-{version}.zip"
    _run_checked(
        [
            sys.executable,
            str(root / "scripts" / "build_plugin.py"),
            "--output",
            str(plugin),
        ],
        root=root,
        env=env,
    )

    skill = output / f"repository-assurance-skill-{version}.zip"
    _run_checked(
        [
            sys.executable,
            str(root / "scripts" / "build_skill.py"),
            "--output",
            str(skill),
        ],
        root=root,
        env=env,
    )

    source = output / f"repo-assurance-source-{version}.tar.gz"
    _run_checked(
        [
            "git",
            "archive",
            "--format=tar.gz",
            f"--prefix=repo-assurance-{version}/",
            f"--output={source}",
            "HEAD",
        ],
        root=root,
        env=env,
    )

    python_artifacts = sorted(
        [
            path
            for path in output.iterdir()
            if path.is_file()
            and (
                path.suffix == ".whl"
                or path.name.endswith(".tar.gz")
                and path != source
            )
        ],
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
