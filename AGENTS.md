# Repository Assurance agent instructions

These instructions apply to coding agents working in this repository.

## Audit tasks

When the user asks to audit, review, assess, or verify repository assurance, first read `skills/repository-assurance/SKILL.md` completely. That file is the canonical audit methodology.

Use the execution order defined there:

1. **CLI-first** — use the local canonical Repository Assurance CLI when executable.
2. **MCP-second** — use the Repo Assurance MCP adapter only when the CLI is unavailable and MCP is connected.
3. **Skill-only fallback** — if neither engine execution surface is available, label the result `PARTIAL_SKILL_GUIDED_AUDIT`.

Do not label a review canonical QUICK/STANDARD/DEEP unless the canonical engine actually executed.

Audit invariants: exact-SHA source provenance, read-only execution, `Unknown != PASS`, current authoritative evidence for time-sensitive claims, and **Preservation beats cleanup**.

## Development tasks

read-only applies to audit execution; explicitly requested development work may edit repository files, add tests, create feature branches, and open PRs under the normal development workflow.

Do not use an audit request as authorization to mutate the audited target. Do not auto-publish releases, deploy, select a software license, or weaken mutation/safety guards without explicit user intent.

## Cross-agent skill assets

`skills/repository-assurance/SKILL.md` is the single canonical skill source.

`.claude/skills/repository-assurance/SKILL.md` and `.opencode/skills/repository-assurance/SKILL.md` are generated exact copies for their respective project discovery paths.

OpenCode discovery is explicitly registered by the minimal project `opencode.json`; do not put provider credentials or other machine-specific settings there.

After changing the canonical skill, run:

`python scripts/sync_agent_assets.py`

CI verifies drift with:

`python scripts/sync_agent_assets.py --check`

Do not hand-edit either generated host skill copy.

## Validation

Before merging substantive changes, run the focused tests first and then the full repository CI-equivalent checks. Preserve the project's evidence/provenance semantics rather than adding platform-specific audit logic.

