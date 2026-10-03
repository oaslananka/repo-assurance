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
- `actionlint` for first-class GitHub Actions syntax/semantic validation (CI-STATIC-001 becomes explicit `UNAVAILABLE` when it is not installed)

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

## ChatGPT local plugin

Repo Assurance can be packaged as an Agent Plugins 1.0 local plugin for ChatGPT Desktop and other hosts that support local stdio MCP servers.

Install the local runtime dependencies from the repository root:

```bash
python -m pip install -e '.[plugin]'
```

Build the standalone plugin package:

```bash
python scripts/build_plugin.py
```

The package contains `plugin.json`, `mcp.json`, the repository-assurance skill, and the read-only Python MCP adapter. The MCP server exposes `discover_repository`, `plan_repository_audit`, `audit_repository`, and `render_audit_report`; it does not expose arbitrary shell execution or remediation/mutation tools.

Local filesystem access requires a host that can launch the stdio MCP process (for example ChatGPT Desktop). Saving the package to a ChatGPT account does not by itself grant local filesystem access on web or mobile.

### Immutable source evidence

Repository profile and workflow-source controls read from the audited Git object (`<target SHA>:<path>`), not from the current checkout. Dirty working-tree state remains separate drift evidence and is never relabeled as target-SHA source evidence.

When `actionlint` is installed, CI-STATIC-001 runs it against the exact audited workflow bytes through stdin. The adapter records actionlint version, workflow target, invocation mode, exit state, and normalized diagnostics. It runs in an isolated temporary directory with shellcheck/pyflakes integrations disabled, does not write into the repository, and does not persist raw workflow bytes or diagnostic source snippets. Missing actionlint is reported as `UNAVAILABLE`, never PASS.

For current-sensitive controls, authoritative baseline evidence can be supplied explicitly:

```bash
repo-assurance audit --repo . --baseline-evidence /path/to/baselines.json
```

`baselines.json` is a `baseline-evidence/v1` object or list. Missing or stale current evidence remains `INCONCLUSIVE`; the engine does not substitute model memory.
