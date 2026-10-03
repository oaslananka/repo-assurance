# repo-assurance

Evidence-driven repository assurance orchestrator.

`repo-assurance` correlates local Git/filesystem evidence, GitHub governance, GitHub Actions operational history, repository hygiene, and current-baseline evidence around an immutable repository snapshot. It is intentionally **read-only**: the auditor reports and orders remediation; it does not mutate repositories.

## Status

The current MVP vertical slice focuses on:

- immutable repository snapshot and local/remote drift;
- repository/language/build-test discovery;
- GitHub rules/protection/check visibility;
- GitHub-native security and dependency assurance (CodeQL/code scanning, secret scanning, dependency graph/SBOM, Dependabot);
- GitHub Actions static and operational health;
- stale/local-only branch and worktree preservation risks;
- deterministic correlation, deduplication, completeness, and reports.

External provider assurance now includes a versioned provider-state contract and initial SonarQube Cloud / Socket GitHub-check adapters. Check execution is treated as execution evidence only; provider issue/alert inventories remain explicit gaps until direct provider evidence is available.

## Installation

For a published CLI release, `pipx` is the recommended installation method because
it keeps the command isolated from application environments:

```bash
pipx install repo-assurance
repo-assurance audit --repo . --mode standard
```

A regular Python environment can use `pip` instead:

```bash
python -m pip install repo-assurance
```

Before the first PyPI publication, or when an exact Git release is preferred, install
the tagged source directly:

```bash
pipx install "git+https://github.com/oaslananka/repo-assurance.git@v0.2.0"
```

Repository cloning is primarily for development:

```bash
git clone https://github.com/oaslananka/repo-assurance.git
cd repo-assurance
python -m pip install -e '.[dev,plugin]'
pytest -q
```

## Requirements

- Python 3.12+
- Git
- `gh` for GitHub live-state collection (audits degrade explicitly when it is unavailable)
- `actionlint` for first-class GitHub Actions syntax/semantic validation (CI-STATIC-001 becomes explicit `UNAVAILABLE` when it is not installed)

The required CI lane uses a reproducible dependency baseline instead of resolving
ranges on every run:

```bash
python -m pip install --require-hashes -r requirements/ci.lock
python -m pip install --no-deps --no-build-isolation -e .
pytest -q
```

See [`references/reproducibility-policy.md`](references/reproducibility-policy.md)
for baseline scope, lock freshness verification, intentional `--upgrade`
regeneration, and the distinction between reproducibility observations and
security findings.

### GitHub Actions supply-chain policy

Remote step actions are expected to be pinned to full 40-character commit SHAs,
including GitHub-authored `actions/*` references. Reusable workflow references are
classified separately. See
[`references/action-reference-policy.md`](references/action-reference-policy.md)
for the threat model, exceptions, and the distinction between immutability and
version freshness.

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

### Self-audit acceptance

The ordinary test suite includes a deterministic offline acceptance test that drives the canonical CLI against an immutable Git target while the checkout has later and dirty changes. It validates report schemas, material finding propagation, blind spots, Markdown rendering, and repository read-only invariants.

An authenticated live GitHub acceptance path is opt-in so normal CI does not depend on external API/provider availability. Run it with:

    REPO_ASSURANCE_RUN_LIVE_ACCEPTANCE=1 pytest -q -m live_github tests/acceptance/test_live_github_acceptance.py

The live acceptance test is permission-aware and does not require SonarQube, Socket, or other external provider dashboards to be reachable.

## Release validation and distribution

Official releases use the Python package version in `pyproject.toml` as the canonical
version. `plugin.json` must match it exactly, and the official plugin/skill artifacts
are built from the same exact tagged commit.

Release validation is deliberately non-publishing. A `vX.Y.Z` tag (or an explicit
manual validation of an existing tag) runs `.github/workflows/release.yml`, which
uses locked dependencies, executes the full validation suite, builds the Python
wheel/sdist, plugin ZIP, skill ZIP, and source archive, then emits
`release-manifest.json` plus `SHA256SUMS`.

For a local validation on a clean tagged checkout:

```bash
python scripts/build_release.py --expected-tag v0.2.0 --output dist/release
cd dist/release
sha256sum --check SHA256SUMS
```

The validation workflow does **not** publish to package indexes, create a GitHub
Release, deploy, or update external plugin registries. Publication is a separate
owner-authorized manual workflow that takes the exact release tag and successful
validation run ID, then reuses the already validated artifact bytes without rebuilding
them.

Publication is intentionally two-stage:

1. run `Publish Validated Release` with target `testpypi`; the workflow publishes
   the validated wheel/sdist with OIDC Trusted Publishing, verifies their SHA-256
   digests against the validated release set, and smoke-tests the staged CLI;
2. run it again with target `production`; the workflow re-verifies the TestPyPI
   stage, publishes the same bytes to PyPI, verifies and smoke-tests the production
   package, and only then creates the GitHub Release.

TestPyPI uses the GitHub environment `testpypi`; production PyPI uses `pypi`.
Both Trusted Publisher configurations must name this repository and
`.github/workflows/publish.yml`. No long-lived package-index API token is required.
PEP 740 attestations are enabled for both package-index uploads.

See `references/release-policy.md`, `references/release-checklist.md`, and
`CHANGELOG.md`.

## Cross-agent local use

Repository Assurance uses one canonical skill source at `skills/repository-assurance/SKILL.md`.

Execution order is intentionally portable:

1. **CLI-first** — local coding agents with shell access should run the canonical `repo-assurance` CLI directly.
2. **MCP-second** — use the Repo Assurance MCP adapter only when the CLI is unavailable and MCP is connected.
3. **Skill-only fallback** — if neither execution surface can run, use the skill-guided workflow and label the result `PARTIAL_SKILL_GUIDED_AUDIT`.

Claude Code discovers the generated project skill at `.claude/skills/repository-assurance/SKILL.md`. OpenCode uses `.opencode/skills/repository-assurance/SKILL.md`, registered by the minimal project `opencode.json`. Both host copies are exact generated copies of the same canonical source. Codex and other repository-aware coding agents receive the same contract through `AGENTS.md`.

The Claude and OpenCode host skills are exact generated copies of the canonical skill. After editing the canonical source, run:

```bash
python scripts/sync_agent_assets.py
python scripts/sync_agent_assets.py --check
```

The second command is enforced in CI to prevent silent drift.

Host discovery can be smoke-tested locally without running an audit:

```bash
claude plugin validate .claude/skills
opencode debug skill --pure
```

The OpenCode output should contain `repository-assurance` with a location under `.opencode/skills/repository-assurance/SKILL.md`. Codex and other repository-instruction-aware agents use the root `AGENTS.md` contract.

For local CLI use:

```bash
python -m pip install -e .
repo-assurance audit --repo . --mode standard
```

Install the `plugin` extra only when a local stdio MCP host actually needs the MCP adapter:

```bash
python -m pip install -e '.[plugin]'
```


## License

Repo Assurance is distributed under the MIT License. See [`LICENSE`](LICENSE).
