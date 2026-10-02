from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Sequence

from repo_assurance.core.schema import SchemaValidationError, validate_document


class CatalogError(ValueError):
    """Raised when the declarative control catalog is invalid."""


class EvaluatorNotFoundError(LookupError):
    """Raised when a control references an evaluator that is not registered."""


_EVALUATORS: dict[str, Callable[..., object]] = {}


def _control_dir() -> Path:
    override = os.environ.get("REPO_ASSURANCE_CONTROL_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "controls"



def validate_catalog_document(payload: object, *, source_name: str = "<memory>") -> list[dict[str, object]]:
    """Validate one control-catalog/v1 document and return its controls."""
    if not isinstance(payload, dict):
        raise CatalogError(f"invalid catalog file {source_name}: expected object")
    if payload.get("schema_version") != "control-catalog/v1":
        raise CatalogError(f"invalid catalog file {source_name}: unsupported schema_version")
    if not isinstance(payload.get("domain"), str) or not payload["domain"]:
        raise CatalogError(f"invalid catalog file {source_name}: missing domain")
    file_controls = payload.get("controls")
    if not isinstance(file_controls, list):
        raise CatalogError(f"invalid catalog file {source_name}: controls must be a list")

    controls: list[dict[str, object]] = []
    seen: set[str] = set()
    for control in file_controls:
        if not isinstance(control, dict):
            raise CatalogError(f"invalid control in {source_name}: expected object")
        try:
            validate_document("control.v1", control)
        except SchemaValidationError as exc:
            raise CatalogError(f"invalid control in {source_name}: {exc}") from exc
        control_id = str(control["id"])
        if control_id in seen:
            raise CatalogError(f"duplicate control id in {source_name}: {control_id}")
        seen.add(control_id)
        controls.append(control)
    return controls

def load_catalog(control_dir: Path | None = None) -> list[dict[str, object]]:
    directory = Path(control_dir) if control_dir is not None else _control_dir()
    controls: list[dict[str, object]] = []
    seen: set[str] = set()

    if not directory.is_dir():
        raise CatalogError(f"control catalog directory does not exist: {directory}")

    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"invalid catalog file {path.name}: {exc}") from exc

        for control in validate_catalog_document(payload, source_name=path.name):
            control_id = str(control["id"])
            if control_id in seen:
                raise CatalogError(f"duplicate control id: {control_id}")
            seen.add(control_id)
            controls.append(control)

    return sorted(controls, key=lambda item: str(item["id"]))


def get_control(
    control_id: str,
    catalog: Sequence[dict[str, object]] | None = None,
) -> dict[str, object]:
    controls = load_catalog() if catalog is None else catalog
    for control in controls:
        if control.get("id") == control_id:
            return control
    raise KeyError(control_id)


def register_evaluator(name: str, evaluator: Callable[..., object]) -> None:
    if not name:
        raise ValueError("evaluator name must not be empty")
    if not callable(evaluator):
        raise TypeError("evaluator must be callable")
    _EVALUATORS[name] = evaluator


def resolve_evaluator(name: str) -> Callable[..., object]:
    try:
        return _EVALUATORS[name]
    except KeyError as exc:
        raise EvaluatorNotFoundError(name) from exc
