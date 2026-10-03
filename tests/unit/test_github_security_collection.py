from __future__ import annotations

import json
import subprocess

from repo_assurance.collectors.github import collect_repository_state
from repo_assurance.collectors.github_security import (
    collect_code_scanning_alerts,
    collect_code_scanning_analyses,
    collect_dependency_sbom,
    collect_dependabot_alerts,
    collect_secret_scanning_alerts,
)


class SequenceRunner:
    def __init__(self, results: list[subprocess.CompletedProcess[str]]) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.results.pop(0)


def cp(payload: object, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess(["gh"], returncode, stdout, stderr)


def test_repository_state_preserves_security_configuration() -> None:
    runner = SequenceRunner([cp({
        "full_name": "acme/demo",
        "default_branch": "main",
        "security_and_analysis": {
            "dependabot_security_updates": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
        },
    })])

    item = collect_repository_state("acme/demo", "a" * 40, runner=runner)[0]

    assert item["observation"]["security_and_analysis"] == {
        "dependabot_security_updates": "enabled",
        "secret_scanning": "enabled",
        "secret_scanning_push_protection": "disabled",
    }


def test_code_scanning_analyses_preserve_target_and_tool_metadata() -> None:
    runner = SequenceRunner([cp([[
        {
            "id": 9,
            "ref": "refs/heads/main",
            "commit_sha": "a" * 40,
            "analysis_key": "dynamic/codeql",
            "category": "/language:python",
            "error": "",
            "created_at": "2026-10-03T00:00:00Z",
            "results_count": 1,
            "rules_count": 43,
            "tool": {"name": "CodeQL", "version": "2.27.1"},
        }
    ]])])

    item = collect_code_scanning_analyses(
        "acme/demo",
        "a" * 40,
        runner=runner,
    )[0]

    assert runner.calls == [[
        "gh", "api", "--paginate", "--slurp",
        "/repos/acme/demo/code-scanning/analyses?per_page=100",
    ]]
    assert item["kind"] == "github_state"
    assert item["observation"]["access_state"] == "AVAILABLE"
    assert item["observation"]["analyses"] == [{
        "id": 9,
        "ref": "refs/heads/main",
        "commit_sha": "a" * 40,
        "analysis_key": "dynamic/codeql",
        "category": "/language:python",
        "error": "",
        "created_at": "2026-10-03T00:00:00Z",
        "results_count": 1,
        "rules_count": 43,
        "tool": {"name": "CodeQL", "version": "2.27.1"},
    }]


def test_secret_scanning_collector_requests_metadata_only_and_never_persists_secret() -> None:
    runner = SequenceRunner([cp(
        json.dumps({
            "number": 7,
            "state": "open",
            "secret_type": "github_pat",
            "secret_type_display_name": "GitHub Personal Access Token",
            "resolution": None,
            "created_at": "2026-10-03T00:00:00Z",
            "updated_at": "2026-10-03T00:00:00Z",
        })
    )])

    item = collect_secret_scanning_alerts(
        "acme/demo",
        "a" * 40,
        runner=runner,
    )[0]

    command = runner.calls[0]
    assert command[:3] == ["gh", "api", "--paginate"]
    assert "--slurp" not in command
    assert "--jq" in command
    jq = command[command.index("--jq") + 1]
    assert "secret_type" in jq
    assert "secret," not in jq
    serialized = json.dumps(item)
    assert '"secret":' not in serialized
    assert item["observation"]["alerts"][0]["secret_type"] == "github_pat"


def test_dependabot_permission_gap_is_explicit() -> None:
    runner = SequenceRunner([
        cp("", returncode=1, stderr="gh: Resource not accessible (HTTP 403)")
    ])

    item = collect_dependabot_alerts(
        "acme/demo",
        "a" * 40,
        runner=runner,
    )[0]

    assert item["kind"] == "dependency_state"
    assert item["observation"]["access_state"] == "UNKNOWN_PERMISSION"
    assert item["visibility"]["permission_limited"] is True


def test_dependency_sbom_normalizes_inventory_metadata_only() -> None:
    runner = SequenceRunner([cp({
        "sbom": {
            "name": "com.github.acme/demo",
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "demo"}, {"name": "jsonschema"}],
            "relationships": [{"relationshipType": "DEPENDS_ON"}],
        }
    })])

    item = collect_dependency_sbom(
        "acme/demo",
        "a" * 40,
        runner=runner,
    )[0]

    assert item["kind"] == "dependency_state"
    assert item["observation"]["sbom"] == {
        "name": "com.github.acme/demo",
        "spdx_version": "SPDX-2.3",
        "packages_count": 2,
        "relationships_count": 1,
    }

def test_code_scanning_alerts_normalize_security_metadata() -> None:
    runner = SequenceRunner([cp([[
        {
            "number": 42,
            "state": "open",
            "created_at": "2026-10-03T00:00:00Z",
            "updated_at": "2026-10-03T00:05:00Z",
            "dismissed_at": None,
            "dismissed_reason": None,
            "tool": {"name": "CodeQL", "version": "2.27.1"},
            "rule": {
                "id": "py/sql-injection",
                "name": "SQL query built from user-controlled sources",
                "security_severity_level": "high",
            },
            "most_recent_instance": {
                "commit_sha": "a" * 40,
                "ref": "refs/heads/main",
                "state": "open",
            },
        }
    ]])])

    item = collect_code_scanning_alerts(
        "acme/demo",
        "a" * 40,
        runner=runner,
    )[0]

    assert runner.calls == [[
        "gh", "api", "--paginate", "--slurp",
        "/repos/acme/demo/code-scanning/alerts?state=open&per_page=100",
    ]]
    alert = item["observation"]["alerts"][0]
    assert alert["number"] == 42
    assert alert["tool"] == {"name": "CodeQL"}
    assert alert["rule"]["id"] == "py/sql-injection"
    assert alert["rule"]["security_severity_level"] == "high"
    assert alert["most_recent_instance"]["commit_sha"] == "a" * 40
