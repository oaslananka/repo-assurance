from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR_NAME = "repo-assurance"

ROOT_FILES = (
    "plugin.json",
    "mcp.json",
    "pyproject.toml",
    "README.md",
)
TREE_PATTERNS = (
    "skills/repository-assurance/**/*",
    "src/repo_assurance/**/*.py",
    "controls/*.json",
    "schemas/*.json",
    "references/*.md",
)


def plugin_files() -> list[Path]:
    files = [ROOT / name for name in ROOT_FILES]
    for pattern in TREE_PATTERNS:
        files.extend(path for path in ROOT.glob(pattern) if path.is_file())
    return sorted(set(files), key=lambda path: path.as_posix())


def build_archive(output: Path) -> Path:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = plugin_files()
    missing = [path for path in files if not path.exists()]
    if missing:
        raise FileNotFoundError(", ".join(str(path) for path in missing))

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(ROOT)
            archive.write(path, Path(PLUGIN_DIR_NAME) / relative)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the standalone Repo Assurance ChatGPT plugin archive.")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "repo-assurance-plugin.zip",
    )
    args = parser.parse_args()
    path = build_archive(args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
