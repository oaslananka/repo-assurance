# Release checklist

Use this checklist for an official `vX.Y.Z` release candidate.

## Before tagging

- [ ] Confirm the intended SemVer change and update `pyproject.toml`.
- [ ] Keep `plugin.json` version exactly aligned with the Python package.
- [ ] Update `CHANGELOG.md` from `[Unreleased]` into the target release section.
- [ ] Confirm the CI dependency lock is current.
- [ ] Run the full test suite, compile validation, control-catalog validation, plugin build, and skill build.
- [ ] Confirm the worktree is clean.
- [ ] Review security/provider findings and any documented accepted residual risk.

## Tag validation

- [ ] Create the exact canonical tag `vX.Y.Z` on the intended commit.
- [ ] Push the tag.
- [ ] Confirm the Release Validation workflow checks out that exact tag.
- [ ] Confirm package/plugin version alignment.
- [ ] Confirm all release validation gates pass.
- [ ] Download the GitHub Actions release artifact and verify `SHA256SUMS`.
- [ ] Confirm `release-manifest.json` records the intended exact commit and artifact hashes.

## Publication boundary

- [ ] Do **not** publish to PyPI, create a GitHub Release, deploy, or update external plugin registries unless the owner has explicitly authorized that publication step.
- [ ] If publication is authorized, use only the previously validated artifact set; do not rebuild from a different commit.

## After an authorized publication

- [ ] Verify published artifacts/checksums against the validated manifest.
- [ ] Record release notes and publication references.
- [ ] Reopen `[Unreleased]` for subsequent development.

