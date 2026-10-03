from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_pypi_release.py"

spec = importlib.util.spec_from_file_location("verify_pypi_release", SCRIPT)
assert spec is not None and spec.loader is not None
verify_pypi_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_pypi_release)


def test_local_distribution_hashes_requires_one_wheel_and_one_sdist(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "repo_assurance-0.2.0-py3-none-any.whl"
    sdist = tmp_path / "repo_assurance-0.2.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")

    hashes = verify_pypi_release.local_distribution_hashes(tmp_path)

    assert hashes == {
        wheel.name: hashlib.sha256(b"wheel").hexdigest(),
        sdist.name: hashlib.sha256(b"sdist").hexdigest(),
    }


def test_require_matching_hashes_rejects_missing_or_changed_files() -> None:
    local = {"repo_assurance-0.2.0.whl": "abc", "repo_assurance-0.2.0.tar.gz": "def"}

    with pytest.raises(ValueError, match="filenames"):
        verify_pypi_release.require_matching_hashes(
            local,
            {"repo_assurance-0.2.0.whl": "abc"},
        )

    with pytest.raises(ValueError, match="SHA-256"):
        verify_pypi_release.require_matching_hashes(
            local,
            {
                "repo_assurance-0.2.0.whl": "abc",
                "repo_assurance-0.2.0.tar.gz": "wrong",
            },
        )


def test_published_distribution_hashes_reads_pypi_json_shape() -> None:
    payload = {
        "urls": [
            {
                "filename": "repo_assurance-0.2.0-py3-none-any.whl",
                "digests": {"sha256": "wheelhash"},
            },
            {
                "filename": "repo_assurance-0.2.0.tar.gz",
                "digests": {"sha256": "sdisthash"},
            },
        ]
    }

    assert verify_pypi_release.published_distribution_hashes(payload) == {
        "repo_assurance-0.2.0-py3-none-any.whl": "wheelhash",
        "repo_assurance-0.2.0.tar.gz": "sdisthash",
    }
