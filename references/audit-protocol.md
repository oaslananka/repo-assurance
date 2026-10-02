# Audit Protocol

## Phase order

1. Establish repository identity and exact target commit SHA.
2. Record dirty state and local/remote drift without changing refs.
3. Discover repository type, languages, package/build/test systems, Actions use, and capabilities.
4. Build an audit plan that accounts for every catalog control.
5. Collect local source/Git and GitHub live evidence.
6. Collect bounded CI history and record the real observation window, retention limits, and permissions.
7. Evaluate controls. `UNKNOWN_PERMISSION`, `UNAVAILABLE`, `INCONCLUSIVE`, and `PASS` are distinct states.
8. Perform preservation analysis before branch/worktree cleanup classification.
9. Resolve time-sensitive facts only from supplied current authoritative evidence.
10. Correlate grounded control findings, deduplicate the same underlying issue, materialize canonical findings, and order remediation.
11. Compute domain-level completeness and list blind spots.
12. Render Markdown from canonical JSON; presentation never changes policy.

## Read-only boundary

Audit mode does not push, merge, delete branches/worktrees/stashes, reset/clean, change GitHub settings, dismiss alerts, publish, deploy, or perform cloud mutation. A future remediation workflow must be separate and explicitly authorized.

## Bounded conclusions

State what was observed, through which source, over which window. Zero visible alerts are not proof that vulnerabilities do not exist. A 403 is a visibility gap, not a clean result.
