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
