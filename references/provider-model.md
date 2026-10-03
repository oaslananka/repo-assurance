# Provider Assurance Model

Repository Assurance treats external provider execution, provider visibility, and provider findings as separate assurance facts.

## Contract

Canonical provider observations conform to `schemas/provider-state.v1.schema.json`.

Each provider state records:

- versioned provider/adapter identity;
- discovery mechanism and source evidence;
- declared capabilities for known adapters only;
- entitlement visibility;
- observed execution status;
- exact audited target binding;
- grounded provider scope when visible;
- issue/alert inventory visibility;
- merge-enforcement state;
- explicit evidence gaps;
- current-baseline requirements when a provider claim needs time-sensitive semantics.

Unknown providers discovered through GitHub checks use the generic `generic-github-check/v1` adapter and receive **no invented capabilities**.

## Initial adapters

### SonarQube Cloud

Detected by GitHub check app slug `sonarqubecloud`.

Grounded check metadata can expose:

- provider execution;
- project key and branch from safe Sonar dashboard parameters;
- whether the check context is required.

The check run does **not** prove Sonar issue inventory visibility, entitlement, quality-gate configuration completeness, or an empty issue set. Those remain explicit gaps until direct provider evidence is available.

### Socket

Detected by GitHub check app slug `socket-security`.

Grounded check metadata can expose:

- provider execution;
- organization and SBOM/project/report scope from the check target;
- whether the check context is required.

The check run does **not** prove Socket alert inventory visibility, entitlement, or an empty dependency-risk inventory.

## Control semantics

- `PROV-001` evaluates observed provider execution only.
- `PROV-002` evaluates issue/alert inventory visibility.
- `PROV-003` evaluates visible provider findings.

A successful `PROV-001` result does not imply `PROV-002` or `PROV-003` PASS.

If no external provider is detected on an otherwise visible GitHub check surface, provider controls are `NOT_ENABLED` rather than findings.

If check/provider visibility is unavailable or permission-limited, the provider domain remains unavailable/partial; it is never converted to PASS.

## Cross-provider correlation

Dependency vulnerability evidence uses stable upstream advisory identity where available.

A provider issue with a `GHSA-*` identifier and a GitHub Dependabot advisory with the same identifier share the canonical root discriminator `dependency-advisory`. Source-specific qualifiers such as provider name, severity, or manifest path remain evidence details and do not split the canonical advisory finding.

## Recommendation policy

Provider recommendations should pass this filter:

`AVAILABLE -> ENTITLED -> APPLICABLE -> MATERIAL GAP -> INCREMENTAL VALUE -> ACCEPTABLE COST/NOISE -> RECOMMEND`

Tool count is not an assurance goal.

