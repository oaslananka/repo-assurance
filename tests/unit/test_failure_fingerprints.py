from __future__ import annotations

from repo_assurance.core.fingerprints import normalize_failure_fingerprint


def test_database_readiness_is_stable_across_noise() -> None:
    first = normalize_failure_fingerprint(
        job_name="integration",
        step_name="wait for postgres",
        message="2026-10-02T10:01:02Z pg_isready: no response on /tmp/pg-1234.sock after 30s",
    )
    second = normalize_failure_fingerprint(
        job_name="integration",
        step_name="Wait for PostgreSQL",
        message="2026-10-02T11:44:55Z connection refused: postgres not ready after 45 seconds",
    )

    assert first == second == "database-readiness"


def test_registry_network_is_detected() -> None:
    assert normalize_failure_fingerprint(
        job_name="build",
        step_name="npm install",
        message="npm ERR! code ETIMEDOUT request to https://registry.npmjs.org/pkg failed",
    ) == "registry-network"


def test_permission_denied_is_detected() -> None:
    assert normalize_failure_fingerprint(
        job_name="deploy-test",
        step_name="write cache",
        message="Permission denied: /home/runner/work/_temp/cache-9371",
    ) == "permission-denied"


def test_snapshot_mismatch_is_detected() -> None:
    assert normalize_failure_fingerprint(
        job_name="test",
        step_name="pytest",
        message="snapshot mismatch: expected output differs from stored snapshot 827",
    ) == "snapshot-mismatch"


def test_runner_unavailable_is_detected() -> None:
    assert normalize_failure_fingerprint(
        job_name="macos",
        step_name=None,
        message="The job was not acquired by a runner within the expected time",
    ) == "runner-unavailable"


def test_unknown_message_returns_unknown_not_raw_message() -> None:
    assert normalize_failure_fingerprint(
        job_name="test",
        step_name="custom",
        message="unexpected custom failure at /tmp/foo/1234",
    ) == "unknown"


def test_empty_input_returns_none() -> None:
    assert normalize_failure_fingerprint(
        job_name=None,
        step_name=None,
        message=None,
    ) is None
