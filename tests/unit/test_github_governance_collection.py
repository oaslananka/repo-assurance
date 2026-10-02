from __future__ import annotations

import json
import subprocess

from repo_assurance.collectors.github import collect_default_branch_state, collect_rulesets


class FakeRunner:
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.result


def cp(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["gh"], 0, stdout, "")


def test_collect_rulesets_preserves_rules_and_bypass_metadata() -> None:
    runner = FakeRunner(cp(json.dumps([{
        "id": 1,
        "name": "main",
        "enforcement": "active",
        "target": "branch",
        "source_type": "Repository",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        "rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "test"}]}}],
    }])))

    evidence = collect_rulesets("acme/demo", "a" * 40, runner=runner)
    ruleset = evidence[0]["observation"]["rulesets"][0]

    assert ruleset["source_type"] == "Repository"
    assert ruleset["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert ruleset["bypass_actors"][0]["bypass_mode"] == "always"
    assert ruleset["rules"][0]["type"] == "required_status_checks"


def test_collect_default_branch_state_normalizes_protection() -> None:
    runner = FakeRunner(cp(json.dumps({
        "name": "main",
        "protected": True,
        "protection": {
            "required_status_checks": {
                "enforcement_level": "non_admins",
                "contexts": ["test", "lint"],
            }
        },
    })))

    evidence = collect_default_branch_state("acme/demo", "main", "a" * 40, runner=runner)

    assert runner.calls == [["gh", "api", "/repos/acme/demo/branches/main"]]
    assert evidence[0]["observation"]["protected"] is True
    assert evidence[0]["observation"]["required_status_checks"] == ["lint", "test"]
