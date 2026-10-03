# GitHub Actions Reference Immutability Policy

## Policy

Repository Assurance treats a remote GitHub Action reference as immutable only when
the action is pinned to a **full 40-character Git commit SHA**.

This policy applies equally to:

- GitHub-authored actions such as `actions/checkout`;
- actions published by verified creators;
- third-party actions from any other owner.

The following are not considered immutable action references:

- major/minor/patch tags such as `@v7` or `@v7.1.2`;
- branches such as `@main`;
- abbreviated commit SHAs;
- unknown/non-versioned remote references.

Local actions (`./path`) are not remote references and are outside this control.
`docker://` step references are also outside this Git-action pinning control and
should be evaluated under container/supply-chain policy when that domain is added.

Job-level reusable workflow references are classified separately. GitHub's native
"Require actions to be pinned to a full-length commit SHA" setting applies to
actions, while reusable workflows may still be referenced by tag. Repository
Assurance therefore does not report a reusable-workflow tag as a CI-STATIC-004
action-pinning finding.

## Threat model

Tags and branches are mutable references. If an action repository or maintainer
account is compromised, a mutable ref can be moved to different code without any
change in the consuming workflow.

A full commit SHA makes the consumed Git object immutable. Repository Assurance
therefore uses immutability—not version freshness—as the decision boundary for
CI-STATIC-004.

## Freshness is a separate concern

CI-STATIC-004 does **not** report a finding merely because a newer action release
exists.

Version freshness, deprecation, runtime support, and end-of-life are separate,
time-sensitive concerns and require current authoritative baseline evidence before
they can become lifecycle findings.

This keeps these questions distinct:

- **Immutability:** is the action reference fixed to exact code?
- **Freshness/lifecycle:** is the selected code still supported and appropriate?

## Repository policy

This repository follows its own rule:

- `actions/checkout` is pinned to the full SHA currently referenced by official
  `v7`.
- `actions/setup-python` is pinned to the full SHA currently referenced by
  official `v7`.
- version comments are retained for maintainability, but the executable reference
  is the SHA.

Pinned SHAs were resolved from the official `actions/checkout` and
`actions/setup-python` repositories on 2026-10-03.

## Authoritative basis

GitHub documents that pinning an action to a full-length commit SHA is currently
the only way to use an action as an immutable release, and that repository or
organization policy can require full-length SHA pinning for all actions,
including actions authored by GitHub.

References:

- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions

## Audit behavior

CI-STATIC-004 reports `FINDING` when any remote step action uses a tag, branch, or
otherwise non-full-SHA reference.

It reports `PASS` when all remote step actions are pinned to full SHAs, with local
actions and `docker://` references excluded from this specific control.

The control is structural and therefore not time-sensitive. Current-baseline
evidence is required only for separate lifecycle/deprecation conclusions.
