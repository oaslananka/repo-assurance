from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "repository-assurance" / "SKILL.md"
PREFIX = "repository-assurance"
ARCHIVE_SKILL_PATH = "repository-assurance/SKILL.md"
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def build_archive(output: Path) -> Path:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if not SKILL.is_file():
        raise FileNotFoundError(SKILL)

    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            _zip_info(ARCHIVE_SKILL_PATH),
            SKILL.read_bytes(),
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the standalone Repository Assurance skill archive."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / "repository-assurance-skill.zip",
    )
    args = parser.parse_args()
    print(build_archive(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
