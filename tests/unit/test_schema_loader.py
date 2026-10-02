from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_assurance.core.schema import (
    SchemaValidationError,
    load_schema,
    validate_document,
)


def test_loads_known_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    (schema_dir / "example.v1.schema.json").write_text(
        json.dumps({"type": "object", "required": ["name"]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("REPO_ASSURANCE_SCHEMA_DIR", str(schema_dir))

    schema = load_schema("example.v1")

    assert schema["type"] == "object"


def test_unknown_schema_name_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPO_ASSURANCE_SCHEMA_DIR", str(tmp_path))

    with pytest.raises(FileNotFoundError):
        load_schema("missing.v1")


def test_invalid_document_raises_schema_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    (schema_dir / "example.v1.schema.json").write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string"}},
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("REPO_ASSURANCE_SCHEMA_DIR", str(schema_dir))

    with pytest.raises(SchemaValidationError):
        validate_document("example.v1", {"name": 123})
