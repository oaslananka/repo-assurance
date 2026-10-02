from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Sequence

from repo_assurance.core.schema import validate_document


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find(evidence: Sequence[dict[str, Any]], evidence_id: str) -> dict[str, Any] | None:
    return next((item for item in evidence if item.get("id") == evidence_id), None)


def _result(
    control_id: str,
    state: str,
    subject: dict[str, Any],
    evidence_ids: list[str],
    reason: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": subject,
        "evidence_ids": evidence_ids,
        "candidate_finding_ids": [],
        "evaluated_at": _now(),
    }
    if reason:
        result["reason"] = reason
    validate_document("control-result.v1", result)
    return result


def evaluate_snapshot(evidence: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    identity = _find(evidence, "ev_git_identity")
    snapshot = _find(evidence, "ev_git_snapshot")
    workspace = _find(evidence, "ev_git_workspace")
    subject = (
        (identity or snapshot or workspace or {}).get("subject")
        or {"type": "repository", "identifier": "unknown"}
    )

    identity_state = "PASS" if identity else "INCONCLUSIVE"
    snapshot_observation = snapshot.get("observation", {}) if snapshot else {}
    target_sha = str(snapshot_observation.get("target_commit_sha", ""))
    commit_state = "PASS" if re.fullmatch(r"[0-9a-fA-F]{40,64}", target_sha) else "INCONCLUSIVE"
    drift = snapshot_observation.get("drift")
    drift_state = "PASS" if drift in {"IN_SYNC", "LOCAL_AHEAD", "LOCAL_BEHIND", "DIVERGED", "DETACHED"} else "INCONCLUSIVE"
    workspace_state = "PASS" if workspace else "INCONCLUSIVE"

    return [
        _result("SNAP-001", identity_state, subject, [identity["id"]] if identity else [], "repository_identity_unavailable" if not identity else None),
        _result("SNAP-002", commit_state, subject, [snapshot["id"]] if snapshot else [], "immutable_commit_unavailable" if commit_state != "PASS" else None),
        _result("SNAP-003", drift_state, subject, [snapshot["id"]] if snapshot else [], "drift_unclassified" if drift_state != "PASS" else None),
        _result("SNAP-004", workspace_state, subject, [workspace["id"]] if workspace else [], "workspace_state_unavailable" if not workspace else None),
    ]
