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

## Specialist workflow validation

CI-STATIC-001 uses actionlint as first-class execution evidence.

- Audited workflow bytes are read from the exact target Git object, not the checkout.
- Raw workflow bytes are sent to actionlint through stdin and are not persisted by the adapter.
- actionlint runs in an isolated temporary working directory so dirty checkout configuration cannot affect the specialist result.
- shellcheck and pyflakes integrations are disabled for deterministic single-tool provenance.
- Stored diagnostics keep message/path/line/column/kind metadata but omit source snippets.
- Missing actionlint is explicit UNAVAILABLE evidence; execution/parsing failures are UNKNOWN_ERROR.
- CI-STATIC-001 reaches PASS only when every specialist workflow result is PASS.

## GitHub-native security and dependency evidence

GitHub security/dependency controls use live GitHub API evidence and preserve permission visibility explicitly.

- Code scanning analyses retain exact commit SHA, ref, tool/version, category, result/rule counts, and analysis error state.
- Code scanning PASS for target coverage requires a successful analysis of the exact audited commit. Historical analysis alone is not target coverage.
- Code scanning and Dependabot alert collectors expose open alert metadata; an empty visible alert list means no open GitHub alerts were returned, not that no vulnerability exists outside the observed coverage.
- Secret scanning alert collection filters at the gh CLI boundary and stores alert metadata only. Secret values are never requested into canonical evidence.
- Repository security_and_analysis state is normalized to status fields only.
- Dependency graph/SBOM evidence records inventory metadata/counts rather than reproducing the full SBOM.
- UNKNOWN_PERMISSION, entitlement gaps, malformed responses, and unavailable surfaces remain explicit and prevent a verified-domain claim.
- Dependabot findings use stable advisory subjects such as GHSA-* where available so later provider adapters can correlate equivalent vulnerability evidence.
