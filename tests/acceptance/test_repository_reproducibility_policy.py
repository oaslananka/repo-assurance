from __future__ import annotations

from pathlib import Path

from repo_assurance.evaluators.repository import discover_repository_profile


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "requirements" / "ci.lock"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_repository_has_hash_locked_ci_baseline() -> None:
    profile = discover_repository_profile(ROOT)
    lock_text = LOCK.read_text(encoding="utf-8")

    assert profile["dependency_reproducibility"] == {
        "state": "LOCKED_BASELINE_OBSERVED",
        "artifacts": ["requirements/ci.lock"],
    }
    assert "--hash=sha256:" in lock_text
    assert "jsonschema==" in lock_text
    assert "pytest==" in lock_text
    assert "mcp==" in lock_text
    assert "setuptools==" in lock_text
    assert "pip-tools==7.6.1" in lock_text


def test_required_ci_uses_locked_baseline_and_fixed_runtime() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "runs-on: ubuntu-24.04" in workflow
    assert 'python-version: "3.12.14"' in workflow
    assert (
        "python -m pip install --require-hashes -r requirements/ci.lock"
        in workflow
    )
    assert (
        "python -m pip install --no-deps --no-build-isolation -e ."
        in workflow
    )
    assert 'python -m pip install -e ".[dev,plugin]"' not in workflow
    assert "python scripts/update_ci_lock.py" in workflow
    assert "git diff --exit-code -- requirements/ci.lock" in workflow


def test_lock_generator_provenance_is_fixed() -> None:
    script = (ROOT / "scripts" / "update_ci_lock.py").read_text(encoding="utf-8")
    lock_text = LOCK.read_text(encoding="utf-8")

    assert 'PIP_TOOLS_VERSION = "7.6.1"' in script
    assert '"--upgrade"' in script
    assert "python scripts/update_ci_lock.py" in lock_text
