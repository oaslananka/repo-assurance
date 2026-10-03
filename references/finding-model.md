# Finding Model

Final findings conform to `schemas/finding.v1.schema.json` and are produced only after control evaluation, correlation, and deduplication.

## Separate dimensions

- **Severity:** impact/risk (`CRITICAL` → `INFO`).
- **Confidence:** strength of evidence (`CONFIRMED` → `LOW`).
- **Priority:** remediation order (`P0` → `P4`).
- **Output class:** `FINDING`, `OBSERVATION`, or `EVIDENCE_GAP`.

A high operational priority does not imply critical security severity.

## Identity

Stable finding fingerprints use semantic inputs (control family, canonical subject, root discriminator), not evidence ordering. This allows future delta audits to distinguish new, unchanged, worsened, and resolved findings.

## Deduplication

Multiple tools reporting the same underlying condition become one canonical finding with multiple evidence references. Native scanner severity is preserved as evidence; it is not blindly copied to canonical severity.

## Remediation

Remediation is guidance only. Tracks are dependency-aware: stabilize a flaky gate before enforcing it; preserve unique local work before cleanup.

## Fail-safe materialization

A material control result must not disappear merely because a specialized correlation rule has not yet been authored.

The canonical correlation contract is:

1. Specialized correlation rules take precedence when they recognize a grounded `FINDING` result.
2. Any remaining grounded `state=FINDING` result is materialized as a conservative `CONTROL_FINDING` candidate.
3. The fallback preserves the evaluator-provided candidate ID(s) when present, linked evidence IDs, control ID, subject, and a stable control-level root discriminator.
4. The fallback uses conservative generic classification until a richer control-specific rule is added.
5. A `FINDING` with missing or unresolvable evidence fails closed with a correlation error; it is not invented from ungrounded state.
6. `PASS`, `INCONCLUSIVE`, `UNAVAILABLE`, `UNKNOWN_PERMISSION`, `UNKNOWN_ERROR`, `NOT_ENABLED`, and `NOT_APPLICABLE` are never promoted by this fallback.

This safeguard exists to prevent silent negative-result loss. It is not a substitute for adding precise correlation semantics, root-cause grouping, severity, and remediation templates for recurring finding classes.
