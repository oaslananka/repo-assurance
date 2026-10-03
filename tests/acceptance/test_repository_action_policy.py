from __future__ import annotations

from pathlib import Path

from repo_assurance.evaluators.cicd_static import inspect_workflow_source


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / '.github' / 'workflows' / 'ci.yml'


def test_repository_ci_remote_actions_are_full_sha_pinned() -> None:
    analysis = inspect_workflow_source(
        '.github/workflows/ci.yml',
        CI_WORKFLOW.read_text(encoding='utf-8'),
    )

    remote_actions = [
        item
        for item in analysis['actions']
        if item['ref_kind'] not in {'local', 'docker'}
    ]

    assert remote_actions
    assert all(item['ref_kind'] == 'full_sha' for item in remote_actions)
