from __future__ import annotations

import json
import subprocess

from repo_assurance.collectors.github import (
    collect_commit_checks,
    collect_default_branch_state,
    collect_rulesets,
)


class FakeRunner:
    def __init__(self, result: subprocess.CompletedProcess[str]) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, argv, *, cwd=None):
        self.calls.append(list(argv))
        return self.result


def cp(payload: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["gh"], 0, json.dumps(payload), "")


def test_collect_rulesets_preserves_rules_and_bypass_metadata() -> None:
    runner = FakeRunner(cp([{
        "id": 1,
        "name": "main",
        "enforcement": "active",
        "target": "branch",
        "source_type": "Repository",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
        "rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "test"}]}}],
    }]))

    evidence = collect_rulesets("acme/demo", "a" * 40, runner=runner)
    ruleset = evidence[0]["observation"]["rulesets"][0]
    assert ruleset["source_type"] == "Repository"
    assert ruleset["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert ruleset["bypass_actors"][0]["bypass_mode"] == "always"
    assert ruleset["rules"][0]["type"] == "required_status_checks"


def test_collect_default_branch_state_normalizes_protection() -> None:
    runner = FakeRunner(cp({
        "name": "main",
        "protected": True,
        "protection": {
            "required_status_checks": {
                "enforcement_level": "non_admins",
                "contexts": ["test", "lint"],
                "checks": [{"context": "test", "app_id": 15368}],
            }
        },
    }))

    evidence = collect_default_branch_state("acme/demo", "main", "a" * 40, runner=runner)

    assert runner.calls == [["gh", "api", "/repos/acme/demo/branches/main"]]
    assert evidence[0]["observation"]["protected"] is True
    assert evidence[0]["observation"]["required_status_checks"] == ["lint", "test"]
    assert evidence[0]["observation"]["required_status_check_details"] == [
        {"context": "lint", "app_id": None},
        {"context": "test", "app_id": 15368},
    ]


def test_collect_commit_checks_normalizes_check_run_identity() -> None:
    runner = FakeRunner(cp({
        "total_count": 3,
        "check_runs": [
            {
                "id": 111,
                "name": "test",
                "status": "completed",
                "conclusion": "success",
                "details_url": "https://github.com/acme/demo/actions/runs/222/job/111",
                "app": {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"},
                "check_suite": {"id": 333},
            },
            {"id": 112, "name": "lint", "details_url": "https://github.com/acme/demo/actions/runs/999/job/112", "app": {"id": 42, "slug": "external"}},
            {"id": 113, "name": "test", "app": {"id": 15368, "slug": "github-actions"}},
        ],
    }))

    evidence = collect_commit_checks("acme/demo", "a" * 40, runner=runner)

    assert runner.calls == [["gh", "api", "/repos/acme/demo/commits/" + "a" * 40 + "/check-runs?per_page=100"]]
    observation = evidence[0]["observation"]
    assert observation["check_names"] == ["lint", "test"]
    first = observation["check_runs"][0]
    assert first["id"] == 111
    assert first["name"] == "test"
    assert first["app_id"] == 15368
    assert first["app_slug"] == "github-actions"
    assert first["check_suite_id"] == 333
    assert first["workflow_run_id"] == 222
    assert first["job_id"] == 111

    external = observation["check_runs"][1]
    assert external["app_slug"] == "external"
    assert external["workflow_run_id"] is None
    assert external["job_id"] is None

def test_provider_check_metadata_is_safely_normalized() -> None:
    runner = FakeRunner(cp({
        "total_count": 1,
        "check_runs": [{
            "id": 200,
            "name": "SonarCloud Code Analysis",
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://sonarcloud.io/dashboard?id=acme_demo&branch=main&token=do-not-store-me",
            "started_at": "2026-10-03T02:59:00Z",
            "completed_at": "2026-10-03T03:00:00Z",
            "app": {
                "id": 12526,
                "slug": "sonarqubecloud",
                "name": "SonarQubeCloud",
            },
            "check_suite": {"id": 444},
        }],
    }))

    evidence = collect_commit_checks("acme/demo", "a" * 40, runner=runner)

    check = evidence[0]["observation"]["check_runs"][0]
    assert "details_url" not in check
    assert check["app_name"] == "SonarQubeCloud"
    assert check["started_at"] == "2026-10-03T02:59:00Z"
    assert check["completed_at"] == "2026-10-03T03:00:00Z"
    assert check["details_host"] == "sonarcloud.io"
    assert check["details_path"] == "/dashboard"
    assert check["details_query"] == {"id": "acme_demo", "branch": "main"}
    assert "token" not in repr(check)

def test_unknown_provider_details_path_is_not_persisted() -> None:
    runner = FakeRunner(cp({
        "total_count": 1,
        "check_runs": [{
            "id": 201,
            "name": "Acme Security",
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://example.invalid/run/opaque-secret-value?token=do-not-store",
            "app": {
                "id": 999,
                "slug": "acme-security",
                "name": "Acme Security",
            },
        }],
    }))

    evidence = collect_commit_checks("acme/demo", "a" * 40, runner=runner)

    check = evidence[0]["observation"]["check_runs"][0]
    assert check["details_host"] is None
    assert check["details_path"] == ""
    assert check["details_query"] == {}
    assert "opaque-secret-value" not in repr(check)
    assert "do-not-store" not in repr(check)
