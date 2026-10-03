---
name: repository-assurance-auditing
description: Use when auditing a local Git repository or GitHub-backed repository for evidence-grounded repository health, CI/CD reliability, governance, security/provider controls, and branch/worktree preservation risks.
---

# Repository Assurance Auditing

The canonical skill source is `skills/repository-assurance/SKILL.md`.

Before performing an audit, read that file completely and follow it as the authoritative Repository Assurance workflow. Do not duplicate the audit methodology here.

Compatibility summary:

- CLI-first when the local canonical `repo-assurance` engine is executable.
- MCP-second when the CLI is unavailable but the Repo Assurance MCP adapter is connected.
- Otherwise use the skill-only fallback and label the result `PARTIAL_SKILL_GUIDED_AUDIT`.
- Audit execution remains read-only; bind source conclusions to an exact commit SHA; Unknown is not clean/PASS; Preservation beats cleanup.

All detailed evidence, history, provider, current-baseline, and provenance rules live in the canonical skill source.
