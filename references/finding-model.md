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
