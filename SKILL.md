---
name: repository-assurance-auditing
description: Use when auditing a GitHub repository, investigating repository health, CI/CD reliability, governance, stale branches or worktrees, security/quality controls, or release readiness.
---

# Repository Assurance Auditing

## Overview

Audit the repository as an evidence-correlation problem, not as a checklist or another scanner. Establish what is actually observable, which controls are effectively operating, and where evidence is incomplete.

**Core invariants:** audit is **read-only**; bind conclusions to an **exact commit SHA**; **Unknown is not clean**; **Preservation beats cleanup**.

## Required workflow

1. Run discovery and lock the audit target. Record repository, target ref, exact commit SHA, dirty state, and local/remote drift.
2. Build the repository-specific plan. Every catalog control must be applicable or explicitly not applicable; never silently skip one.
3. Collect local Git/filesystem evidence, GitHub live state, CI history, and detected provider evidence without mutation.
4. For time-sensitive claims, obtain **current authoritative evidence**. Prefer official documentation, changelogs, advisories, registries, then upstream sources. If current evidence cannot be verified, report an evidence gap.
5. Evaluate controls, correlate independent evidence, deduplicate the same underlying issue, and preserve provenance.
6. Run preservation analysis before recommending branch/worktree/stash cleanup. Local-only commits, detached unique commits, dirty worktrees, or remote-deleted surviving work require preservation/review first.
7. Report findings, remediation ordering, and **audit completeness**. Keep severity, confidence, priority, and visibility distinct.

Canonical execution:

```bash
repo-assurance audit --repo <path> --mode standard
```

Use `quick` for triage and `deep` only when broader dynamic/current evidence is justified. Use `--offline` when GitHub live/API collection or external current-baseline resolution must be skipped; the resulting GitHub/CI-history domains remain unavailable or partial rather than being treated as clean. Do not substitute model memory for current facts.

## Bounded claims

Phrase conclusions to match the evidence window and permissions. “No alerts observed through the available API access” is valid when supported. Never report “No vulnerabilities exist” merely because a provider returned zero findings or an endpoint was inaccessible.

Map inaccessible or incomplete surfaces to explicit states such as `UNKNOWN_PERMISSION`, `UNAVAILABLE`, `PARTIAL`, or `INCONCLUSIVE`; never convert them to PASS.

## Tool and provider recommendations

Do not maximize tool count. Recommend a new provider only when it is available/entitled, applicable to this repository, covers a material gap, adds meaningful incremental assurance, and has acceptable operational noise or cost. Overlap is not automatically redundancy.

## Common mistakes

| Mistake | Correct behavior |
| --- | --- |
| Old branch ⇒ delete | Check reachability, PR relation, unique commits, worktrees, and stashes first. |
| Existing workflow ⇒ healthy CI | Inspect retained execution history, chronic failure, flakiness, dead jobs, and enforcement. |
| Scanner PASS ⇒ effective control | Verify execution freshness, target coverage, and merge enforcement. |
| 403/hidden data ⇒ zero findings | Record visibility limitation and bound the conclusion. |
| Current recommendation from memory | Resolve current authoritative evidence or mark it unverified. |
