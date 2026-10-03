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

## One-time PyPI prerequisite

- [ ] Confirm the intended PyPI project name is available or already controlled by the owner.
- [ ] Configure a PyPI Trusted Publisher for repository `oaslananka/repo-assurance`, workflow `publish.yml`, and GitHub environment `pypi`.
- [ ] Do not add a long-lived PyPI API token to repository secrets.

## Publication boundary

- [ ] Do **not** publish to PyPI, create a GitHub Release, deploy, or update external plugin registries unless the owner has explicitly authorized that publication step.
- [ ] Run `Publish Validated Release` manually with the exact tag and successful validation run ID.
- [ ] Use only the previously validated artifact set; do not rebuild from a different commit.
- [ ] Choose `github`, `pypi`, or `both` explicitly for the publication target.

## After an authorized publication

- [ ] Verify the GitHub Release assets/checksums against the validated manifest when GitHub publication was selected.
- [ ] Verify the PyPI version, wheel, sdist, project metadata, and provenance when PyPI publication was selected.
- [ ] Record publication references.
- [ ] Reopen `[Unreleased]` for subsequent development.
