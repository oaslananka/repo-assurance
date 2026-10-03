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
- [ ] Record the successful Release Validation run ID.
- [ ] Download the GitHub Actions release artifact and verify `SHA256SUMS`.
- [ ] Confirm `release-manifest.json` records the intended exact commit and artifact hashes.

## One-time package-index prerequisites

- [ ] Confirm the intended project name is available or already controlled on both PyPI and TestPyPI.
- [ ] Configure a TestPyPI Trusted Publisher for repository `oaslananka/repo-assurance`, workflow `publish.yml`, and GitHub environment `testpypi`.
- [ ] Configure a PyPI Trusted Publisher for repository `oaslananka/repo-assurance`, workflow `publish.yml`, and GitHub environment `pypi`.
- [ ] Confirm both GitHub environments exist and contain no long-lived package-index credential.
- [ ] Do not add PyPI/TestPyPI API tokens to repository or environment secrets.

## Publication boundary

- [ ] Do **not** publish to TestPyPI, PyPI, create a GitHub Release, deploy, or update external plugin registries unless the owner has explicitly authorized that publication step.
- [ ] Run `Publish Validated Release` with target `testpypi`, the exact tag, and the successful validation run ID.
- [ ] Confirm TestPyPI filename/digest verification and CLI smoke testing succeed.
- [ ] Run `Publish Validated Release` again with target `production`, using the same exact tag and validation run ID.
- [ ] Confirm the production gate re-verifies the staged TestPyPI bytes before PyPI publication.
- [ ] Use only the previously validated artifact set; do not rebuild from a different commit.
- [ ] Confirm PyPI filename/digest verification and production CLI smoke testing succeed before the GitHub Release is created.

## After an authorized publication

- [ ] Verify the GitHub Release assets/checksums against the validated manifest.
- [ ] Verify the PyPI version, wheel, sdist, project metadata, and PEP 740 provenance.
- [ ] Record the validation run, staging run, production run, and publication references.
- [ ] Reopen `[Unreleased]` for subsequent development.
