# Evidence Model

Canonical evidence conforms to `schemas/evidence.v1.schema.json`.

Core evidence kinds include source, Git state, GitHub live state/history, execution, provider state, dependency state, external-current evidence, inference, and user-declared context.

Every evidence item carries:

- stable evidence ID and canonical subject;
- source/provider/mechanism/collector provenance;
- repository + target commit snapshot;
- collection time and optional freshness;
- visibility completeness, permission limitation, and retention limitation;
- sanitized observations and optional raw-artifact provenance.

## Rules

1. Absence of evidence is never converted into evidence of absence.
2. `inference` is lower-strength than direct source/API/execution evidence.
3. Sensitive values are removed at the normalization boundary. Secret type/location may be retained; secret values may not.
4. Two reports are not automatically independent evidence. Future provider adapters should retain upstream lineage when known.
5. Current-baseline evidence must carry authority and checked date; stale or insufficient-authority evidence cannot satisfy a current claim.

## Required merge-gate identity

A required status-check context is not the same identity as a workflow.

Repository Assurance resolves GitHub Actions merge-gate enforcement through an evidence chain:

`required status-check context -> check-run/app identity -> workflow run/job -> workflow id/name/path`

Rules:

- Match required contexts to check-runs by exact context name; do not fuzzy-match workflow names.
- When branch protection or a ruleset pins an app/integration ID, the observed check-run must match that identity.
- Parse GitHub Actions run/job linkage only from checks produced by the GitHub Actions app.
- Map the check-run's workflow run ID to workflow-history evidence before classifying a workflow as required.
- If one required context maps to multiple workflows, or the check/run/history link is missing, the mapping is incomplete.
- Incomplete or permission-limited mapping is explicit inference evidence and must not be converted into `workflow_not_required` PASS.
- Gate-sensitive control results reference both workflow-history evidence and the normalized required-gate mapping evidence.
