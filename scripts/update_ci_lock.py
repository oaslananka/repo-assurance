from __future__ import annotations

import argparse
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "ci.lock"
PIP_TOOLS_VERSION = "7.6.1"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Regenerate the reproducible CI dependency baseline."
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Allow pip-compile to refresh pinned dependency versions.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if sys.version_info[:2] != (3, 12):
        raise SystemExit(
            "CI lock generation requires CPython 3.12; "
            f"got {sys.version_info.major}.{sys.version_info.minor}"
        )

    try:
        installed_version = version("pip-tools")
    except PackageNotFoundError as exc:
        raise SystemExit(
            f"pip-tools=={PIP_TOOLS_VERSION} is required; install it in a clean "
            "Python 3.12 environment before regenerating the lock."
        ) from exc
    if installed_version != PIP_TOOLS_VERSION:
        raise SystemExit(
            f"pip-tools=={PIP_TOOLS_VERSION} is required; got {installed_version}."
        )

    LOCK.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "compile",
        "--all-build-deps",
        "--all-extras",
        "--generate-hashes",
        "--strip-extras",
        "--allow-unsafe",
        "--quiet",
        "--no-emit-index-url",
        "--no-emit-trusted-host",
        "--output-file",
        str(LOCK.relative_to(ROOT)),
        "pyproject.toml",
    ]
    if args.upgrade:
        command.insert(-1, "--upgrade")

    from piptools.__main__ import cli

    previous_cwd = Path.cwd()
    previous_compile_command = os.environ.get("CUSTOM_COMPILE_COMMAND")
    try:
        os.chdir(ROOT)
        os.environ["CUSTOM_COMPILE_COMMAND"] = "python scripts/update_ci_lock.py"
        cli.main(
            args=command,
            prog_name="python -m piptools",
            standalone_mode=False,
        )
    finally:
        os.chdir(previous_cwd)
        if previous_compile_command is None:
            os.environ.pop("CUSTOM_COMPILE_COMMAND", None)
        else:
            os.environ["CUSTOM_COMPILE_COMMAND"] = previous_compile_command
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
