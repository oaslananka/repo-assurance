# Changelog

All notable user-visible changes to Repo Assurance are recorded here.

The format is based on Keep a Changelog and the project uses Semantic Versioning for official releases.

## [Unreleased]

## [0.2.1] - 2026-10-03

### Fixed

- Ship the canonical control catalog and JSON schemas with Python distributions so `plan`, `audit`, and `validate` work from normal `pip`/`pipx` installations outside a source checkout.
- Release and publication smoke gates now install the built wheel in an isolated environment and load its control catalog and schemas, preventing parser-only checks from missing runtime packaging regressions.

## [0.2.0] - 2026-10-03

### Added

- Non-publishing release validation, exact-commit artifact provenance, deterministic plugin/skill packaging, and release checksums.
- Cross-agent CLI-first execution with generated Claude Code and OpenCode skill assets, repository-level agent instructions, and explicit skill-only provenance.
- MIT License and package metadata for public reuse and redistribution.
- Manual public publication workflow for GitHub Releases and PyPI that reuses an already validated exact-tag artifact set.

### Changed

- End-user installation documentation now prioritizes published CLI installation with `pipx` or `pip` instead of requiring a repository clone.

## [0.1.1] - 2026-10-03

### Added

- Evidence-driven repository assurance engine, CLI, control catalogs, reports, ChatGPT plugin adapter, standalone skill, GitHub governance analysis, CI operational analysis, Git hygiene, provider/security assurance, and current-baseline support.
