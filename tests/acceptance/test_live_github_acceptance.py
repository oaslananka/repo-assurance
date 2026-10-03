from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from repo_assurance.cli import main
from repo_assurance.core.schema import validate_document


RUN_LIVE = os.environ.get("REPO_ASSURANCE_RUN_LIVE_ACCEPTANCE") == "1"
ROOT = Path(__file__).resolve().parents[2]


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.mark.live_github
@pytest.mark.skipif(
    not RUN_LIVE,
    reason="set REPO_ASSURANCE_RUN_LIVE_ACCEPTANCE=1 for authenticated live acceptance",
)
def test_live_github_self_audit_is_permission_aware(tmp_path: Path) -> None:
    target_sha = git("rev-parse", "HEAD")
    before_status = git("status", "--porcelain=v1")
    before_refs = git("for-each-ref", "--format=%(refname) %(objectname)")
    output = tmp_path / "live-acceptance"

    assert main([
        "audit",
        "--repo",
        str(ROOT),
        "--target",
        target_sha,
        "--mode",
        "standard",
        "--debug-evidence",
        "--output",
        str(output),
    ]) == 0

    report = json.loads((output / "audit-report.json").read_text(encoding="utf-8"))
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    validate_document("audit-report.v1", report)

    assert report["snapshot"]["target_commit_sha"] == target_sha

    history = [
        item
        for item in evidence
        if item.get("source", {}).get("collector") == "github-actions-history/v1"
    ]
    available_history = [
        item
        for item in history
        if item.get("observation", {}).get("access_state") in {"AVAILABLE", "PARTIAL"}
    ]
    if available_history:
        for item in available_history:
            for run in item.get("observation", {}).get("runs", []):
                assert isinstance(run.get("id"), int)
                assert isinstance(run.get("head_sha"), str)
                assert len(run["head_sha"]) == 40
                assert run.get("created_at")
    else:
        assert report["coverage"]["ci_history"] in {
            "UNAVAILABLE",
            "UNKNOWN_PERMISSION",
            "PARTIAL",
        }

    for domain, state in report["coverage"].items():
        assert state in {
            "VERIFIED",
            "PARTIAL",
            "UNAVAILABLE",
            "UNKNOWN_PERMISSION",
            "NOT_APPLICABLE",
        }, (domain, state)

    assert git("rev-parse", "HEAD") == target_sha
    assert git("status", "--porcelain=v1") == before_status
    assert git("for-each-ref", "--format=%(refname) %(objectname)") == before_refs
