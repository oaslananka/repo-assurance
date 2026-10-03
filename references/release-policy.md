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

## Release validation

The Release Validation workflow runs on `v*` tags and explicit `workflow_dispatch` validation. It:

1. checks out the exact requested tag with full history;
2. uses the repository's pinned CPython baseline;
3. installs hash-locked dependencies from `requirements/ci.lock`;
4. runs the full test/compile/catalog validation gates;
5. runs `scripts/build_release.py`;
6. installs the built wheel into a temporary environment and verifies that the installed package can load the shipped control catalog, JSON schemas, and CLI parser without relying on the source checkout;
7. verifies `SHA256SUMS`;
8. uploads the release artifact directory as a GitHub Actions artifact.

Release Validation is deliberately **non-publishing**. It uses read-only repository permissions and does not publish to PyPI, create a GitHub Release, update a plugin registry, or deploy anything.

## Authorized publication

Creating a public GitHub Release or publishing to a package index requires **explicit authorization** after a successful Release Validation run.

`.github/workflows/publish.yml` is manual-only and accepts:

- the exact existing release tag;
- the successful Release Validation workflow run ID for that tag;
- a publication stage: `testpypi` or `production`.

The publication workflow does not rebuild the project. It verifies that the supplied run is a successful Release Validation run for the exact tag commit, downloads that run's named artifact set, verifies `SHA256SUMS` and `release-manifest.json`, and reuses those exact bytes.

### TestPyPI staging

Run the `testpypi` stage first. It publishes only the validated wheel and source distribution through the GitHub environment named `testpypi` using OpenID Connect Trusted Publishing. PEP 740 attestations are enabled explicitly.

After upload, the workflow waits for TestPyPI metadata, compares the published wheel/sdist filenames and SHA-256 digests with the validated artifacts, installs the exact validated wheel into a temporary environment, and verifies package version, control-catalog loading, schema loading, and the CLI parser.

### Production publication

Run the `production` stage only after TestPyPI staging succeeds. Before any production credential is requested, the workflow independently re-checks that TestPyPI still exposes exactly the validated wheel/sdist bytes and repeats the CLI smoke test.

The production job then publishes the same validated distributions through the GitHub environment named `pypi` using OpenID Connect Trusted Publishing with PEP 740 attestations. It does not use `skip-existing`; duplicate or partial production versions fail loudly.

After upload, the workflow verifies PyPI filenames and SHA-256 digests against the validated artifacts and repeats the installed-wheel runtime verification. Only after those checks pass does it create the GitHub Release and attach the complete validated artifact set.

Both package-index environments are credentialless from the repository's perspective: no long-lived PyPI or TestPyPI API token belongs in repository or environment secrets. The corresponding Trusted Publisher configuration is a one-time external prerequisite for each index.

Publication attempts for the same release tag are serialized with a workflow concurrency group. Do not rebuild or silently replace an already published version.

## Security and provenance

Release automation must preserve:

- exact-SHA provenance;
- full-SHA-pinned remote GitHub Actions;
- locked dependency installation during validation;
- no secret-bearing publishing credentials in the validation workflow;
- PyPI and TestPyPI Trusted Publishing with short-lived OIDC identity;
- PEP 740 attestations for wheel and source-distribution uploads;
- package-index filename and SHA-256 verification before advancing release stages;
- no mutation of repository source during artifact construction;
- publication only from the already validated artifact set.

A version number alone is not evidence that a release is approved or published.
