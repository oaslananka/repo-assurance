# repo-assurance

Evidence-driven repository assurance orchestrator.

`repo-assurance` correlates local Git/filesystem evidence, GitHub governance, GitHub Actions operational history, repository hygiene, and current-baseline evidence around an immutable repository snapshot. It is intentionally **read-only**: the auditor reports and orders remediation; it does not mutate repositories.

## Status

The current MVP vertical slice focuses on:

- immutable repository snapshot and local/remote drift;
- repository/language/build-test discovery;
- GitHub rules/protection/check visibility;
- GitHub Actions static and operational health;
- stale/local-only branch and worktree preservation risks;
- deterministic correlation, deduplication, completeness, and reports.

Third-party provider adapters (Codecov, SonarQube Cloud, Semgrep, Codacy, Mergify, etc.) remain gated until the core exit criteria are satisfied.

## Requirements

- Python 3.12+
- Git
- `gh` for GitHub live-state collection (audits degrade explicitly when it is unavailable)

Development:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

## CLI

Discover repository facts without producing findings:

```bash
repo-assurance discover --repo .
```

Build the repository-specific plan:

```bash
repo-assurance plan --repo . --mode standard
```

Run a read-only audit:

```bash
repo-assurance audit --repo . --mode standard
```

Offline audit, using local/static evidence only and skipping GitHub live/API collection and current external baseline resolution:

```bash
repo-assurance audit --repo . --mode standard --offline
```

Validate canonical output:

```bash
repo-assurance validate report /path/to/audit-report.json
```

Render a canonical JSON report as Markdown:

```bash
repo-assurance render /path/to/audit-report.json --format markdown
```

Unless `--output` is supplied, audit artifacts are written to a temporary directory outside the audited repository so the worktree remains clean.

## Architecture boundaries

- **Collector ≠ policy.** Collectors report observable facts.
- **Evidence ≠ finding.** Controls interpret normalized evidence.
- **Scanner severity ≠ canonical severity.** External severities remain evidence inputs.
- **Unknown ≠ pass.** Permission, retention, and availability gaps remain explicit.
- **Preservation beats cleanup.** Unique/dirty local work blocks cleanup recommendations.
- **Renderer ≠ evaluator.** Markdown is rendered from canonical JSON and cannot recompute findings.

See `references/` for the audit protocol and extension contracts.

## Project layout

- `schemas/` — versioned canonical JSON contracts.
- `controls/` — declarative first-slice control catalog.
- `src/repo_assurance/collectors/` — policy-blind evidence collection.
- `src/repo_assurance/evaluators/` — control evaluation.
- `src/repo_assurance/core/` — planning, correlation, dedupe, findings, completeness, remediation.
- `src/repo_assurance/renderers/` — canonical report presentation.
- `tests/` — unit, integration, golden, safety, and skill-contract tests.
