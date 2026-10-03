# Release policy

Repo Assurance uses **Semantic Versioning** for official source and artifact releases.

## Canonical version

The Python package version in `pyproject.toml` is the canonical release version.

For an official release:

- the Python package and ChatGPT plugin metadata MUST use the same version;
- the official standalone skill artifact uses the same canonical version in its filename;
- the Git tag is `vX.Y.Z` (or the corresponding SemVer prerelease form);
- every official artifact is traceable to one **exact commit**.

Ad hoc skill ZIPs used during development are test artifacts and are not official releases merely because their filenames contain a version-like label.

## Compatibility

The plugin and official skill artifact are released from the same exact source commit as the core engine. Their instructions/adapters may expose different execution surfaces, but they must not claim compatibility with a different engine revision without an explicit compatibility policy.

## Release notes

`CHANGELOG.md` follows a Keep-a-Changelog-style structure with an `[Unreleased]` section. Before an official release, move user-visible changes into the release version section and summarize breaking behavior, assurance-model changes, security implications, and migration notes when applicable.

## Artifact set

A validated release build produces:

- Python wheel and source distribution;
- ChatGPT plugin ZIP;
- standalone skill ZIP;
- exact-commit source archive;
- `release-manifest.json`;
- `SHA256SUMS`.

`release-manifest.json` records the canonical version, tag, exact Git commit, artifact names, sizes, and SHA-256 digests. `SHA256SUMS` provides a standard checksum surface for the distributable artifacts.

## Clean tagged source requirement

Official artifacts MUST be built from a clean worktree whose HEAD is exactly the canonical release tag. The release builder rejects:

- package/plugin version drift;
- malformed release versions;
- dirty source state;
- an expected tag that does not match the canonical version;
- a tag that does not point at exact HEAD.

Generated output under `dist/` is ignored by Git and is not part of the source state.

## CI and GitHub release validation

The release workflow runs on `v*` tags and explicit `workflow_dispatch` validation. It:

1. checks out the exact requested tag with full history;
2. uses the repository's pinned CPython baseline;
3. installs hash-locked dependencies from `requirements/ci.lock`;
4. runs the full test/compile/catalog validation gates;
5. runs `scripts/build_release.py`;
6. verifies `SHA256SUMS`;
7. uploads the release artifact directory as a GitHub Actions artifact.

The workflow is deliberately **non-publishing**. It uses read-only repository permissions and does not publish to PyPI, create a GitHub Release, update a plugin registry, or deploy anything.

Creating a public GitHub Release or publishing any artifact to an external registry requires **explicit authorization** and is a separate action after the validated artifact set exists.

## Security and provenance

Release automation must preserve:

- exact-SHA provenance;
- full-SHA-pinned remote GitHub Actions;
- locked dependency installation;
- no secret-bearing publishing credentials in the validation workflow;
- no mutation of repository source during artifact construction.

A version number alone is not evidence that a release is approved or published.

