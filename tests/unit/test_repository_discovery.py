from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repo_assurance.evaluators.repository import (
    discover_repository_profile,
    discover_repository_profile_at_commit,
    evaluate_repository_profile,
)


def test_discovers_python_library(tmp_path: Path) -> None:
    (tmp_path / "src" / "demo").mkdir(parents=True)
    (tmp_path / "src" / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_demo.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\n\n[tool.pytest.ini_options]\ntestpaths=['tests']\n",
        encoding="utf-8",
    )

    profile = discover_repository_profile(tmp_path)

    assert profile["repository_type"] == "library"
    assert profile["languages"] == ["python"]
    assert "python" in profile["package_managers"]
    assert "python -m build" in profile["build_command_candidates"]
    assert "pytest" in profile["test_command_candidates"]


def test_discovers_node_cli_and_npm_commands(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("export {}\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-cli",
                "bin": {"demo": "dist/index.js"},
                "scripts": {"build": "tsc", "test": "vitest run"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    profile = discover_repository_profile(tmp_path)

    assert profile["repository_type"] == "cli"
    assert profile["languages"] == ["typescript"]
    assert profile["package_managers"] == ["npm"]
    assert profile["lockfiles"] == ["package-lock.json"]
    assert profile["build_command_candidates"] == ["npm run build"]
    assert profile["test_command_candidates"] == ["npm test"]


def test_mixed_python_and_node_repo_is_classified_mixed(tmp_path: Path) -> None:
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "app.tsx").write_text("export default null\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='backend'\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"name": "frontend"}), encoding="utf-8")

    profile = discover_repository_profile(tmp_path)

    assert profile["repository_type"] == "mixed"
    assert profile["languages"] == ["python", "typescript"]
    assert profile["package_managers"] == ["npm", "python"]


def test_detects_github_actions_without_reading_generated_or_vendor_trees(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "fake.py").write_text("print('vendor')\n", encoding="utf-8")
    node_modules = tmp_path / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "fake.ts").write_text("export {}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs\n", encoding="utf-8")

    profile = discover_repository_profile(tmp_path)

    assert profile["github_actions"] is True
    assert profile["languages"] == []
    assert profile["repository_type"] == "documentation"


def test_discovery_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")

    first = discover_repository_profile(tmp_path)
    second = discover_repository_profile(tmp_path)

    assert first == second


def test_python_ci_lock_is_reproducibility_observation(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\ndependencies=['jsonschema>=4']\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "ci.lock").write_text(
        "jsonschema==4.25.1 --hash=sha256:deadbeef\n",
        encoding="utf-8",
    )

    profile = discover_repository_profile(tmp_path)

    assert profile["lockfiles"] == ["requirements/ci.lock"]
    assert profile["dependency_reproducibility"] == {
        "state": "LOCKED_BASELINE_OBSERVED",
        "artifacts": ["requirements/ci.lock"],
    }


def test_missing_reproducibility_artifact_is_observation_not_finding(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\ndependencies=['jsonschema>=4']\n",
        encoding="utf-8",
    )
    (tmp_path / "demo.py").write_text("print('ok')\n", encoding="utf-8")

    profile = discover_repository_profile(tmp_path)
    results = evaluate_repository_profile({
        "id": "ev_repository_profile",
        "subject": {"type": "repository", "identifier": "acme/demo"},
        "observation": profile,
    })

    assert profile["dependency_reproducibility"] == {
        "state": "NOT_OBSERVED",
        "artifacts": [],
    }
    assert all(item["state"] != "FINDING" for item in results)


def test_constraints_baseline_is_descriptive_observation(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\ndependencies=['jsonschema>=4']\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "constraints.txt").write_text(
        "jsonschema==4.26.0\n", encoding="utf-8"
    )

    profile = discover_repository_profile(tmp_path)

    assert profile["lockfiles"] == []
    assert profile["dependency_reproducibility"] == {
        "state": "CONSTRAINTS_BASELINE_OBSERVED",
        "artifacts": ["requirements/constraints.txt"],
    }


def test_reproducibility_profile_is_bound_to_target_commit(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.com"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Fixture"],
        cwd=tmp_path,
        check=True,
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='demo'\ndependencies=['jsonschema>=4']\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "ci.lock").write_text(
        "jsonschema==4.25.1 --hash=sha256:deadbeef\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "locked"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    target_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    (requirements / "ci.lock").unlink()
    (tmp_path / "demo.py").write_text("print('later')\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "remove lock"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    profile = discover_repository_profile_at_commit(tmp_path, target_sha)

    assert profile["lockfiles"] == ["requirements/ci.lock"]
    assert profile["dependency_reproducibility"] == {
        "state": "LOCKED_BASELINE_OBSERVED",
        "artifacts": ["requirements/ci.lock"],
    }
