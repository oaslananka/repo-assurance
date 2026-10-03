---
name: repository-assurance
description: Use when auditing a local Git repository or GitHub-backed repository for evidence-grounded repository health, CI/CD reliability, governance, and branch/worktree preservation risks.
---

# Repository Assurance

Use the Repo Assurance MCP tools as the executable source of truth. The workflow is **read-only**: do not delete branches/worktrees/stashes, push commits, merge PRs, dismiss alerts, change GitHub settings, publish, deploy, or otherwise mutate the audited repository.

## Workflow

1. Call `discover_repository` to establish repository identity, exact target commit SHA, dirty state, repository type, and capabilities.
2. Call `plan_repository_audit` when the user wants scope/applicability before execution or when audit breadth needs explanation.
3. Call `audit_repository` for findings. Prefer `standard`; use `quick` for triage and `deep` when the user explicitly wants broader evidence collection.
4. Use `offline=true` when external GitHub access is unavailable or unwanted. Never substitute model memory for missing current/live evidence.
5. Call `render_audit_report` only to present an existing canonical report. Rendering must not recompute findings.

## Invariants

- **Unknown is not PASS.** Permission errors, unavailable endpoints, retention limits, and missing evidence remain explicit blind spots.
- **Preservation beats cleanup.** Local-only commits, detached unique work, dirty worktrees, or remote-deleted surviving work must be preserved/reviewed before cleanup is recommended.
- Bind conclusions to the exact audited commit SHA and observed history window.
- Keep severity, confidence, remediation priority, and coverage/completeness distinct.
- Do not claim "no vulnerabilities exist" merely because no alerts were visible.
- Do not expose raw secret values. The canonical audit report is the preferred result surface.

## Snapshot and execution provenance

- **Never mix commits into one audit snapshot.** Every finding must retain the exact commit SHA that supplied its source evidence. Cross-branch comparisons are separate observations and must name each branch/SHA explicitly.
- **Historical CI evidence may span commits by design.** Snapshot immutability applies to source/configuration state, not to bounded operational history. For chronic failure, flakiness, dead-workflow, and reliability analysis, use runs across the declared observation window while preserving each run's `head_sha`, workflow identity, and timestamps. If the workflow definition materially changed during the window, split the history or mark the result partial/mixed-configuration instead of discarding all cross-SHA history.
- **A deleted remote branch is not itself a preservation finding.** Do not emit `HYGIENE-004`, `HYGIENE-010`, or another preservation-risk candidate unless there is evidence of surviving local/other unique work. A historical SHA with no current remote ref and no local-survival evidence is an observation only. Absence of local evidence is `UNAVAILABLE`/unknown, not proof of surviving work.
- **Skill-only outputs use explicit provenance.** If `audit_repository` was not actually executed, label the result as `PARTIAL_SKILL_GUIDED_AUDIT` and treat control IDs, finding types, severity, confidence, and priority as advisory candidates unless produced by the canonical engine.
- **MCP/engine availability is part of provenance.** If the Repo Assurance MCP tools are unavailable, do not present the result as a canonical `quick`, `standard`, or `deep` engine execution. Label it as **`PARTIAL_SKILL_GUIDED_AUDIT`**, identify which engine-backed controls were not executed, and keep their coverage unavailable/partial.
- For time-sensitive controls, use current authoritative evidence (official documentation, changelog, advisory, or registry data) and pass normalized `baseline-evidence/v1` items to `audit_repository` when the tool is available. If current evidence cannot be verified, keep the control inconclusive.

## Local runtime

The local MCP server requires Python 3.12+ and the plugin extra installed in the plugin source/runtime environment:

`python -m pip install -e '.[plugin]'`

Local MCP execution is intended for ChatGPT Desktop or another host that can launch the stdio server. Account upload alone does not make local filesystem access available on web/mobile.
