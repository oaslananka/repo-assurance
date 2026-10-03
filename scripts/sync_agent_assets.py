from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SKILL = ROOT / "skills" / "repository-assurance" / "SKILL.md"
CLAUDE_SKILL = ROOT / ".claude" / "skills" / "repository-assurance" / "SKILL.md"
OPENCODE_SKILL = ROOT / ".opencode" / "skills" / "repository-assurance" / "SKILL.md"


def expected_assets() -> dict[Path, bytes]:
    if not CANONICAL_SKILL.is_file():
        raise FileNotFoundError(CANONICAL_SKILL)
    # Host skills are exact generated replicas. Byte comparison is intentional:
    # text/newline normalization would hide encoding or line-ending drift.
    content = CANONICAL_SKILL.read_bytes()
    return {CLAUDE_SKILL: content, OPENCODE_SKILL: content}


def sync_assets() -> list[Path]:
    written: list[Path] = []
    for path, content in expected_assets().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        written.append(path)
    return written


def drifted_assets() -> list[Path]:
    drifted: list[Path] = []
    for path, content in expected_assets().items():
        if not path.is_file() or path.read_bytes() != content:
            drifted.append(path)
    return drifted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync or verify cross-agent Repository Assurance skill assets."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if generated agent assets differ from the canonical skill.",
    )
    args = parser.parse_args()

    if args.check:
        drifted = drifted_assets()
        if drifted:
            for path in drifted:
                print(f"drifted agent asset: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0

    for path in sync_assets():
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

