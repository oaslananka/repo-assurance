from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


class SchemaValidationError(ValueError):
    """Raised when a canonical document does not satisfy its JSON schema."""


def _schema_dir() -> Path:
    override = os.environ.get("REPO_ASSURANCE_SCHEMA_DIR")
    if override:
        return Path(override)
    source_directory = Path(__file__).resolve().parents[3] / "schemas"
    if source_directory.is_dir():
        return source_directory
    return Path(sys.prefix) / "share" / "repo-assurance" / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    path = _schema_dir() / f"{name}.schema.json"
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_document(schema_name: str, document: object) -> None:
    schema = load_schema(schema_name)
    validator = Draft202012Validator(schema)
    try:
        validator.validate(document)
    except ValidationError as exc:
        raise SchemaValidationError(exc.message) from exc
