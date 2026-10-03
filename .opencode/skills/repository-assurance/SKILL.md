---
name: repository-assurance
description: Use when auditing a local Git repository or GitHub-backed repository for evidence-grounded repository health, CI/CD reliability, governance, security/provider controls, and branch/worktree preservation risks.
---

# Repository Assurance

Use the canonical Repository Assurance engine as the executable source of truth whenever an execution surface is available. Audit execution is **read-only**: do not delete branches/worktrees/stashes, push commits, merge PRs, dismiss alerts, change GitHub settings, publish, deploy, or otherwise mutate the audited repository.

## Execution hierarchy

1. **CLI-first** — When the local Repository Assurance CLI is available, run the canonical engine locally. Prefer:

   `repo-assurance audit --repo <path> --mode standard`

   Use `repo-assurance discover` and `repo-assurance plan` when discovery or applicability needs to be shown separately. A source checkout may use `python -m repo_assurance ...` when the console script is not installed but the package is importable.

2. **MCP-second** — If the local CLI is unavailable but the Repo Assurance MCP tools are connected, use `discover_repository`, `plan_repository_audit`, `audit_repository`, and `render_audit_report` as the adapter over the same canonical engine.

3. **skill-only fallback** — If neither the CLI nor the Repo Assurance MCP engine can actually execute, perform only an evidence-guided review and label it `PARTIAL_SKILL_GUIDED_AUDIT`. Treat control IDs, finding types, severity, confidence, and priority as advisory candidates unless produced by the canonical engine.

Canonical `QUICK`, `STANDARD`, or `DEEP` provenance is valid only when the canonical engine actually executed and returned/generated the canonical audit result. Source code presence, a skill file, or an MCP configuration file is not proof that the engine ran.

## Workflow

1. Establish repository identity and lock the audit target to the exact audited commit SHA.
2. Build the repository-specific plan. Every catalog control must be applicable or explicitly not applicable; never silently skip one.
3. Collect local Git/filesystem evidence, GitHub live state, CI history, current authoritative baselines, and detected provider evidence without mutation.
4. Evaluate controls, correlate independent evidence, deduplicate the same underlying issue, and preserve provenance.
5. Run preservation analysis before recommending branch/worktree/stash cleanup.
6. Report findings, remediation ordering, blind spots, and audit completeness.
7. Render an existing canonical report without recomputing findings when a separate presentation step is needed.

Use `quick` for bounded triage, `standard` for normal assurance work, and `deep` only when broader evidence collection is justified. Use offline mode when GitHub/external access is unavailable or intentionally disabled; affected domains remain unavailable/partial rather than clean.

## Invariants

- **Unknown is not PASS.** Permission errors, unavailable endpoints, retention limits, missing tools, and missing evidence remain explicit blind spots.
- **Preservation beats cleanup.** Local-only commits, detached unique work, dirty worktrees, or remote-deleted surviving work must be preserved/reviewed before cleanup is recommended.
- Bind source/config conclusions to the **exact audited commit SHA** and operational conclusions to a declared history window.
- Keep severity, confidence, remediation priority, and coverage/completeness distinct.
- Do not claim "no vulnerabilities exist" merely because no alerts were visible.
- Do not expose raw secret values. Retain only safe type/location/fingerprint-style metadata when useful.
- Current time-sensitive claims require current authoritative evidence; model memory is not a current-baseline source.

## Snapshot and execution provenance

- **Never mix commits into one audit snapshot.** Every source/config finding must retain the exact commit SHA that supplied its evidence. Cross-branch comparisons are separate observations and must name each branch/SHA explicitly.
- **Historical CI evidence may span commits by design.** Snapshot immutability applies to source/configuration state, not to bounded operational history. For chronic failure, flakiness, dead-workflow, and reliability analysis, use runs across the declared observation window while preserving each run's `head_sha`, workflow identity, and timestamps. If the workflow definition materially changed during the window, split the history or mark the result partial/mixed-configuration instead of discarding all cross-SHA history.
- **A deleted remote branch is not itself a preservation finding.** Do not emit `HYGIENE-004`, `HYGIENE-010`, or another preservation-risk candidate unless there is evidence of surviving local/other unique work. A historical SHA with no current remote ref and no local-survival evidence is an observation only. Absence of local evidence is `UNAVAILABLE`/unknown, not proof of surviving work.
- If canonical execution did not occur, keep engine-backed coverage unavailable/partial and use `PARTIAL_SKILL_GUIDED_AUDIT` rather than impersonating a canonical run.

## Bounded claims

Phrase conclusions to match the evidence window and permissions. "No alerts observed through the available API access" is valid when supported. Never report "No vulnerabilities exist" merely because a provider returned zero findings or an endpoint was inaccessible.

Map inaccessible or incomplete surfaces to explicit states such as `UNKNOWN_PERMISSION`, `UNAVAILABLE`, `PARTIAL`, or `INCONCLUSIVE`; never convert them to PASS.

## Tool and provider recommendations

Do not maximize tool count. Recommend a provider only when it is available/entitled, applicable to this repository, covers a material gap, adds meaningful incremental assurance, and has acceptable operational noise/cost. Reuse specialist tools instead of reimplementing mature scanners.

## Audit vs development work

The read-only contract applies to the **audit workflow**. When a user explicitly asks the coding agent to develop Repository Assurance itself, ordinary source edits, tests, feature branches, and PRs are allowed under the repository's development process. Do not use an audit request as implicit authorization to mutate the audited target.

## Local runtime

- Canonical CLI: Python 3.12+ with the package installed, for example `python -m pip install -e .`.
- Optional local MCP adapter: install the plugin extra with `python -m pip install -e '.[plugin]'`, then launch `python -m repo_assurance.mcp_server` from a host that supports local stdio MCP.
- Local coding agents should prefer the CLI when they already have shell access; MCP is optional and should solve a real tool/service boundary rather than duplicate local execution.
