from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repo_assurance.collectors.filesystem import list_commit_paths, read_commit_text

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.12+ invariant
    tomllib = None  # type: ignore[assignment]


_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}
_LANGUAGE_SUFFIXES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
}


def _iter_source_files(repo: Path):
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(repo)
        except ValueError:
            continue
        if any(part in _IGNORED_DIRS for part in relative.parts[:-1]):
            continue
        yield relative, path


def _load_package_json(repo: Path) -> dict[str, Any] | None:
    path = repo / "package.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_pyproject(repo: Path) -> dict[str, Any] | None:
    path = repo / "pyproject.toml"
    if not path.is_file() or tomllib is None:
        return None
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _node_manager(repo: Path) -> str | None:
    if not (repo / "package.json").is_file():
        return None
    if (repo / "pnpm-lock.yaml").is_file():
        return "pnpm"
    if (repo / "yarn.lock").is_file():
        return "yarn"
    return "npm"


def _repository_type(
    *,
    languages: list[str],
    package_json: dict[str, Any] | None,
    pyproject: dict[str, Any] | None,
    repo: Path,
) -> str:
    has_python = pyproject is not None or "python" in languages
    has_node = package_json is not None or any(lang in languages for lang in ("javascript", "typescript"))
    if has_python and has_node:
        return "mixed"
    if (repo / "action.yml").is_file() or (repo / "action.yaml").is_file():
        return "github_action"
    if package_json and package_json.get("bin"):
        return "cli"
    if not languages:
        documentation_files = list(repo.glob("*.md")) + list(repo.glob("docs/**/*.md"))
        if documentation_files:
            return "documentation"
        return "unknown"
    if has_python or has_node:
        return "library"
    return "unknown"


def discover_repository_profile(repo: Path) -> dict[str, object]:
    repo = repo.resolve()
    package_json = _load_package_json(repo)
    pyproject = _load_pyproject(repo)

    languages = sorted(
        {
            language
            for relative, _ in _iter_source_files(repo)
            if (language := _LANGUAGE_SUFFIXES.get(relative.suffix.lower())) is not None
        }
    )

    lockfiles = sorted(
        name
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock")
        if (repo / name).is_file()
    )

    package_managers: set[str] = set()
    node_manager = _node_manager(repo)
    if node_manager:
        package_managers.add(node_manager)
    if pyproject is not None or (repo / "requirements.txt").is_file():
        package_managers.add("python")

    build_commands: list[str] = []
    test_commands: list[str] = []

    if pyproject is not None:
        if "build-system" in pyproject:
            build_commands.append("python -m build")
        tool = pyproject.get("tool")
        if isinstance(tool, dict) and "pytest" in tool:
            test_commands.append("pytest")
        elif (repo / "tests").is_dir():
            test_commands.append("pytest")

    if package_json is not None and node_manager is not None:
        scripts = package_json.get("scripts")
        if isinstance(scripts, dict):
            if "build" in scripts:
                build_commands.append(f"{node_manager} run build")
            if "test" in scripts:
                test_commands.append("npm test" if node_manager == "npm" else f"{node_manager} test")

    github_actions = any(
        path.is_file()
        for path in (repo / ".github" / "workflows").glob("*.y*ml")
    ) if (repo / ".github" / "workflows").is_dir() else False

    return {
        "repository_type": _repository_type(
            languages=languages,
            package_json=package_json,
            pyproject=pyproject,
            repo=repo,
        ),
        "languages": languages,
        "package_managers": sorted(package_managers),
        "lockfiles": lockfiles,
        "github_actions": github_actions,
        "build_command_candidates": sorted(set(build_commands)),
        "test_command_candidates": sorted(set(test_commands)),
    }




def discover_repository_profile_at_commit(repo: Path, target_commit_sha: str) -> dict[str, object]:
    """Discover repository profile strictly from the immutable target Git tree."""
    paths = list_commit_paths(repo, target_commit_sha)
    path_set = set(paths)

    package_json: dict[str, Any] | None = None
    package_text = read_commit_text(repo, target_commit_sha, "package.json") if "package.json" in path_set else None
    if package_text is not None:
        try:
            payload = json.loads(package_text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            package_json = payload

    pyproject: dict[str, Any] | None = None
    pyproject_text = read_commit_text(repo, target_commit_sha, "pyproject.toml") if "pyproject.toml" in path_set else None
    if pyproject_text is not None and tomllib is not None:
        try:
            payload = tomllib.loads(pyproject_text)
        except tomllib.TOMLDecodeError:
            payload = None
        if isinstance(payload, dict):
            pyproject = payload

    def ignored(relative: str) -> bool:
        parts = Path(relative).parts
        return any(part in _IGNORED_DIRS for part in parts[:-1])

    languages = sorted({
        language
        for relative in paths
        if not ignored(relative)
        if (language := _LANGUAGE_SUFFIXES.get(Path(relative).suffix.lower())) is not None
    })

    lockfiles = sorted(
        name
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock")
        if name in path_set
    )

    package_managers: set[str] = set()
    node_manager: str | None = None
    if package_json is not None:
        if "pnpm-lock.yaml" in path_set:
            node_manager = "pnpm"
        elif "yarn.lock" in path_set:
            node_manager = "yarn"
        else:
            node_manager = "npm"
        package_managers.add(node_manager)
    if pyproject is not None or "requirements.txt" in path_set:
        package_managers.add("python")

    build_commands: list[str] = []
    test_commands: list[str] = []
    if pyproject is not None:
        if "build-system" in pyproject:
            build_commands.append("python -m build")
        tool = pyproject.get("tool")
        has_tests = any(path == "tests" or path.startswith("tests/") for path in paths)
        if isinstance(tool, dict) and "pytest" in tool:
            test_commands.append("pytest")
        elif has_tests:
            test_commands.append("pytest")

    if package_json is not None and node_manager is not None:
        scripts = package_json.get("scripts")
        if isinstance(scripts, dict):
            if "build" in scripts:
                build_commands.append(f"{node_manager} run build")
            if "test" in scripts:
                test_commands.append("npm test" if node_manager == "npm" else f"{node_manager} test")

    has_python = pyproject is not None or "python" in languages
    has_node = package_json is not None or any(lang in languages for lang in ("javascript", "typescript"))
    if has_python and has_node:
        repository_type = "mixed"
    elif "action.yml" in path_set or "action.yaml" in path_set:
        repository_type = "github_action"
    elif package_json and package_json.get("bin"):
        repository_type = "cli"
    elif not languages:
        repository_type = "documentation" if any(path.endswith(".md") for path in paths) else "unknown"
    elif has_python or has_node:
        repository_type = "library"
    else:
        repository_type = "unknown"

    github_actions = any(
        path.startswith(".github/workflows/") and Path(path).suffix.lower() in {".yml", ".yaml"}
        for path in paths
    )

    return {
        "repository_type": repository_type,
        "languages": languages,
        "package_managers": sorted(package_managers),
        "lockfiles": lockfiles,
        "github_actions": github_actions,
        "build_command_candidates": sorted(set(build_commands)),
        "test_command_candidates": sorted(set(test_commands)),
    }

def evaluate_repository_profile(profile_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    from datetime import datetime, timezone

    from repo_assurance.core.schema import validate_document

    observation = profile_evidence.get("observation", {})
    subject = profile_evidence.get("subject") or {"type": "repository", "identifier": "unknown"}
    evidence_id = str(profile_evidence.get("id", "ev_repository_profile"))

    def result(control_id: str, state: str, reason: str) -> dict[str, Any]:
        item = {
            "schema_version": "control-result/v1",
            "control_id": control_id,
            "state": state,
            "subject": dict(subject),
            "evidence_ids": [evidence_id],
            "candidate_finding_ids": [],
            "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "reason": reason,
        }
        validate_document("control-result.v1", item)
        return item

    repo_type = observation.get("repository_type") if isinstance(observation, dict) else None
    classification_state = "PASS" if repo_type and repo_type != "unknown" else "INCONCLUSIVE"
    classification_reason = f"repository_type:{repo_type or 'unknown'}"

    languages = observation.get("languages", []) if isinstance(observation, dict) else []
    ecosystem_state = "PASS" if isinstance(languages, list) else "INCONCLUSIVE"
    ecosystem_reason = "ecosystem_inventory_collected" if ecosystem_state == "PASS" else "ecosystem_inventory_unavailable"

    build_commands = observation.get("build_command_candidates") if isinstance(observation, dict) else None
    test_commands = observation.get("test_command_candidates") if isinstance(observation, dict) else None
    command_state = "PASS" if isinstance(build_commands, list) and isinstance(test_commands, list) else "INCONCLUSIVE"
    command_reason = "command_discovery_completed" if command_state == "PASS" else "command_discovery_unavailable"

    return [
        result("REPO-001", classification_state, classification_reason),
        result("REPO-002", ecosystem_state, ecosystem_reason),
        result("REPO-003", command_state, command_reason),
    ]
