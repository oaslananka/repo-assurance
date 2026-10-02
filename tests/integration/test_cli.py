from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from repo_assurance.cli import build_parser, main
from repo_assurance.core.schema import validate_document


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "demo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "config", "user.name", "Fixture")
    (repo / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools']\n\n[tool.pytest.ini_options]\ntestpaths=['tests']\n",
        encoding="utf-8",
    )
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        """name: CI
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
""",
        encoding="utf-8",
    )
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    git(repo, "remote", "add", "origin", "https://github.com/acme/demo.git")
    git(repo, "update-ref", "refs/remotes/origin/main", git(repo, "rev-parse", "HEAD"))
    return repo


def test_discover_outputs_repository_profile_without_writing_repo(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = init_repo(tmp_path)
    before = git(repo, "status", "--porcelain=v1")

    assert main(["discover", "--repo", str(repo)]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["repository"]["full_name"] == "acme/demo"
    assert payload["profile"]["github_actions"] is True
    assert payload["profile"]["languages"] == ["python"]
    assert git(repo, "status", "--porcelain=v1") == before


def test_plan_outputs_schema_valid_plan_and_accounts_for_catalog(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = init_repo(tmp_path)

    assert main(["plan", "--repo", str(repo), "--mode", "standard"]) == 0

    plan = json.loads(capsys.readouterr().out)
    validate_document("audit-plan.v1", plan)
    assert plan["repository"]["full_name"] == "acme/demo"
    assert len(plan["controls"]) == 29
    assert any(item["control_id"] == "CI-OPS-003" for item in plan["controls"])


def test_audit_offline_writes_outputs_outside_repo_and_keeps_repo_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = init_repo(tmp_path)
    before = git(repo, "status", "--porcelain=v1")

    assert main(["audit", "--repo", str(repo), "--mode", "standard", "--offline"]) == 0

    summary = json.loads(capsys.readouterr().out)
    output_dir = Path(summary["output_dir"])
    assert output_dir.is_dir()
    assert repo not in output_dir.parents and output_dir != repo
    plan_path = Path(summary["plan"])
    report_path = Path(summary["report_json"])
    markdown_path = Path(summary["report_markdown"])
    assert plan_path.is_file()
    assert report_path.is_file()
    assert markdown_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_document("audit-report.v1", report)
    assert report["repository"]["full_name"] == "acme/demo"
    assert report["snapshot"]["target_commit_sha"] == git(repo, "rev-parse", "HEAD")
    assert report["coverage"]["snapshot"] == "VERIFIED"
    assert report["coverage"]["github_governance"] in {"UNAVAILABLE", "PARTIAL"}
    assert git(repo, "status", "--porcelain=v1") == before


def test_validate_and_render_commands_use_canonical_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = init_repo(tmp_path)
    output = tmp_path / "out"
    assert main(["audit", "--repo", str(repo), "--mode", "quick", "--offline", "--output", str(output)]) == 0
    capsys.readouterr()

    report_path = output / "audit-report.json"
    assert main(["validate", "report", str(report_path)]) == 0
    assert "valid" in capsys.readouterr().out.lower()

    assert main(["render", str(report_path), "--format", "markdown"]) == 0
    markdown = capsys.readouterr().out
    assert "# Repository Assurance Audit" in markdown


def test_cli_exposes_no_mutation_flags() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "--fix" not in help_text
    assert "--apply" not in help_text
    assert "--delete" not in help_text
    assert "--remediate" not in help_text

    with pytest.raises(SystemExit):
        parser.parse_args(["audit", "--repo", ".", "--fix"])


def test_pyproject_exposes_repo_assurance_console_script() -> None:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert '[project.scripts]' in text
    assert 'repo-assurance = "repo_assurance.cli:main"' in text


def test_validate_control_accepts_control_catalog_file(capsys: pytest.CaptureFixture[str]) -> None:
    catalog_path = Path(__file__).resolve().parents[2] / "controls" / "snapshot.v1.json"

    assert main(["validate", "control", str(catalog_path)]) == 0

    output = capsys.readouterr().out.lower()
    assert "valid" in output
    assert "control" in output


def test_offline_remote_audit_never_calls_github_live_collectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import repo_assurance.cli as cli_module

    repo = init_repo(tmp_path)

    def fail_live_collection(*args, **kwargs):
        raise AssertionError("offline audit must not call GitHub live collectors")

    monkeypatch.setattr(cli_module, "_governance_evidence", fail_live_collection)
    monkeypatch.setattr(cli_module, "_actions_history_evidence", fail_live_collection)

    assert main(["audit", "--repo", str(repo), "--offline"]) == 0

    summary = json.loads(capsys.readouterr().out)
    report = json.loads(Path(summary["report_json"]).read_text(encoding="utf-8"))
    assert report["coverage"]["github_governance"] == "UNAVAILABLE"
    assert report["coverage"]["ci_history"] == "UNAVAILABLE"


def test_governance_collection_uses_live_repository_default_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import repo_assurance.cli as cli_module

    seen_branches: list[str] = []
    sha = "a" * 40

    monkeypatch.setattr(
        cli_module,
        "collect_repository_state",
        lambda repository, target_sha: [
            {
                "id": "ev_github_repository",
                "observation": {
                    "access_state": "AVAILABLE",
                    "default_branch": "main",
                },
            }
        ],
    )
    monkeypatch.setattr(cli_module, "collect_rulesets", lambda repository, target_sha: [])
    monkeypatch.setattr(
        cli_module,
        "collect_default_branch_state",
        lambda repository, branch, target_sha: (
            seen_branches.append(branch) or [{"id": "ev_github_default_branch"}]
        ),
    )
    monkeypatch.setattr(cli_module, "collect_commit_checks", lambda repository, target_sha: [])

    cli_module._governance_evidence("acme/demo", "feature/topic", sha)

    assert seen_branches == ["main"]


def test_required_check_names_include_active_default_branch_rulesets() -> None:
    import repo_assurance.cli as cli_module

    governance = [
        {
            "id": "ev_github_default_branch",
            "observation": {
                "access_state": "AVAILABLE",
                "required_status_checks": ["classic-check"],
            },
        },
        {
            "id": "ev_github_rulesets",
            "observation": {
                "access_state": "AVAILABLE",
                "rulesets": [
                    {
                        "enforcement": "active",
                        "target": "branch",
                        "conditions": {
                            "ref_name": {
                                "include": ["~DEFAULT_BRANCH"],
                                "exclude": [],
                            }
                        },
                        "rules": [
                            {
                                "type": "required_status_checks",
                                "parameters": {
                                    "required_status_checks": [
                                        {"context": "ruleset-check"}
                                    ]
                                },
                            }
                        ],
                    }
                ],
            },
        },
    ]

    assert cli_module._required_check_names(governance) == {
        "classic-check",
        "ruleset-check",
    }

def test_target_snapshot_source_evidence_ignores_checkout_and_dirty_worktree(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = init_repo(tmp_path)
    target_sha = git(repo, "rev-parse", "HEAD")

    (repo / "app.py").unlink()
    (repo / "package.json").write_text(
        json.dumps({"name": "later", "scripts": {"test": "vitest run"}}),
        encoding="utf-8",
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        """name: LATER
permissions: write-all
jobs:
  test:
    runs-on: macos-14
""",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "later checkout")
    workflow.write_text("name: DIRTY\n", encoding="utf-8")

    assert main(["discover", "--repo", str(repo), "--target", target_sha]) == 0
    discovered = json.loads(capsys.readouterr().out)
    assert discovered["snapshot"]["target_commit_sha"] == target_sha
    assert discovered["profile"]["languages"] == ["python"]
    assert discovered["profile"]["package_managers"] == ["python"]

    output = tmp_path / "audit-target"
    assert main([
        "audit", "--repo", str(repo), "--target", target_sha,
        "--offline", "--debug-evidence", "--output", str(output),
    ]) == 0
    capsys.readouterr()
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    workflow_evidence = next(
        item for item in evidence if item.get("subject", {}).get("identifier") == ".github/workflows/ci.yml"
    )
    assert "name: CI" in workflow_evidence["observation"]["text"]
    assert "LATER" not in workflow_evidence["observation"]["text"]
    assert "DIRTY" not in workflow_evidence["observation"]["text"]
    assert workflow_evidence["snapshot"]["target_commit_sha"] == target_sha


def test_supplied_current_baseline_reaches_ci_static_evaluator(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = init_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        """name: CI
permissions: read-all
jobs:
  test:
    runs-on: macos-14
    steps:
      - run: pytest
""",
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "use retiring runner")

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({
        "schema_version": "baseline-evidence/v1",
        "subject": "github-actions/macos-14",
        "claim": "runner lifecycle",
        "status": "retiring",
        "effective_dates": {"retirement": "2026-11-02"},
        "source": {
            "authority": "official",
            "publisher": "GitHub",
            "url": "https://github.blog/changelog/example",
        },
        "checked_at": "2026-10-02T12:00:00Z",
    }), encoding="utf-8")

    output = tmp_path / "audit-baseline"
    assert main([
        "audit", "--repo", str(repo), "--offline",
        "--baseline-evidence", str(baseline_path), "--output", str(output),
    ]) == 0
    capsys.readouterr()
    report = json.loads((output / "audit-report.json").read_text(encoding="utf-8"))
    ci_static_008 = next(
        item for item in report["control_results"] if item["control_id"] == "CI-STATIC-008"
    )
    assert ci_static_008["state"] == "FINDING"
    assert ci_static_008["reason"] == "runner_lifecycle_risk:macos-14=retiring"
    assert any(item["type"] == "DEPRECATION_RISK" for item in report["findings"])

