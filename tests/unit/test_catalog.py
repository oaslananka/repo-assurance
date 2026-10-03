from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_assurance.core.catalog import (
    CatalogError,
    EvaluatorNotFoundError,
    get_control,
    load_catalog,
    register_evaluator,
    resolve_evaluator,
)


def control(control_id: str, evaluator: str = "snapshot.identity") -> dict:
    return {
        "schema_version": "control/v1",
        "id": control_id,
        "title": control_id,
        "domain": "test",
        "description": "Fixture control.",
        "evaluator": evaluator,
        "applicability": {"all_capabilities": [], "any_capabilities": [], "excluded_repository_types": []},
        "evidence_requirements": {"minimum_kinds": ["source"], "minimum_items": 1},
        "evaluation": {"time_sensitive": False, "correlation_required": False, "dynamic_execution": False},
        "outputs": {"allowed_states": ["PASS", "FINDING", "INCONCLUSIVE"]},
    }


def write_catalog(path: Path, domain: str, controls: list[dict]) -> None:
    path.write_text(
        json.dumps({"schema_version": "control-catalog/v1", "domain": domain, "controls": controls}),
        encoding="utf-8",
    )


def test_load_catalog_rejects_duplicate_control_ids(tmp_path: Path) -> None:
    write_catalog(tmp_path / "a.json", "a", [control("TEST-001")])
    write_catalog(tmp_path / "b.json", "b", [control("TEST-001")])

    with pytest.raises(CatalogError, match="duplicate control id"):
        load_catalog(tmp_path)


def test_load_catalog_rejects_invalid_control_schema(tmp_path: Path) -> None:
    invalid = control("TEST-001")
    invalid["outputs"]["allowed_states"] = []
    write_catalog(tmp_path / "invalid.json", "test", [invalid])

    with pytest.raises(CatalogError, match="invalid control"):
        load_catalog(tmp_path)


def test_load_catalog_is_deterministically_sorted_by_control_id(tmp_path: Path) -> None:
    write_catalog(tmp_path / "z.json", "z", [control("TEST-020"), control("TEST-002")])
    write_catalog(tmp_path / "a.json", "a", [control("TEST-010")])

    catalog = load_catalog(tmp_path)

    assert [item["id"] for item in catalog] == ["TEST-002", "TEST-010", "TEST-020"]


def test_get_control_returns_exact_control(tmp_path: Path) -> None:
    write_catalog(tmp_path / "one.json", "test", [control("TEST-001")])
    catalog = load_catalog(tmp_path)

    assert get_control("TEST-001", catalog)["id"] == "TEST-001"


def test_resolve_unknown_evaluator_fails() -> None:
    with pytest.raises(EvaluatorNotFoundError):
        resolve_evaluator("fixture.unknown")


def test_registered_evaluator_can_be_resolved() -> None:
    def fixture_evaluator():
        return "ok"

    register_evaluator("fixture.known", fixture_evaluator)

    assert resolve_evaluator("fixture.known") is fixture_evaluator


def test_shipped_catalog_contains_exact_first_slice_controls() -> None:
    expected = {
        "SNAP-001", "SNAP-002", "SNAP-003", "SNAP-004",
        "REPO-001", "REPO-002", "REPO-003",
        "GH-GOV-001", "GH-GOV-003", "GH-GOV-007", "GH-GOV-008",
        "GH-SEC-001", "GH-SEC-002", "GH-SEC-003",
        "DEP-001", "DEP-002", "DEP-003",
        "PROV-001", "PROV-002", "PROV-003",
        "CI-STATIC-001", "CI-STATIC-003", "CI-STATIC-004", "CI-STATIC-006", "CI-STATIC-008",
        "CI-OPS-001", "CI-OPS-002", "CI-OPS-003", "CI-OPS-005", "CI-OPS-006", "CI-OPS-007", "CI-OPS-008",
        "HYGIENE-001", "HYGIENE-003", "HYGIENE-004", "HYGIENE-005", "HYGIENE-008", "HYGIENE-010",
    }

    catalog = load_catalog()

    assert {item["id"] for item in catalog} == expected
