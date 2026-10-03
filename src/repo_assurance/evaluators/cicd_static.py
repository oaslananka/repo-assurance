from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


_ACTION_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
_RUNNER_RE = re.compile(r"^\s*runs-on:\s*([^#]+?)\s*$")
_TOP_PERMISSIONS_RE = re.compile(r"^permissions:\s*(.*?)\s*$")
_FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_TAG_LIKE_RE = re.compile(r"^v?\d+(?:\.\d+)*(?:[-._][A-Za-z0-9]+)*$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _non_comment_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def _classify_action_ref(uses: str) -> dict[str, Any]:
    if uses.startswith("./"):
        return {"uses": uses, "ref_kind": "local", "third_party": False, "ref": None}
    if uses.startswith("docker://"):
        return {"uses": uses, "ref_kind": "docker", "third_party": False, "ref": None}
    if "@" not in uses:
        return {"uses": uses, "ref_kind": "unknown", "third_party": True, "ref": None}

    repository, ref = uses.rsplit("@", 1)
    if _FULL_SHA_RE.fullmatch(ref):
        ref_kind = "full_sha"
    elif _TAG_LIKE_RE.fullmatch(ref):
        ref_kind = "tag"
    else:
        ref_kind = "branch"

    owner = repository.split("/", 1)[0].lower() if "/" in repository else repository.lower()
    return {
        "uses": uses,
        "ref_kind": ref_kind,
        "third_party": owner not in {"actions", "github"},
        "ref": ref,
    }


def _classify_reusable_workflow_ref(uses: str) -> dict[str, Any]:
    if uses.startswith("./"):
        return {"uses": uses, "ref_kind": "local", "ref": None}
    if "@" not in uses:
        return {"uses": uses, "ref_kind": "unknown", "ref": None}

    _, ref = uses.rsplit("@", 1)
    if _FULL_SHA_RE.fullmatch(ref):
        ref_kind = "full_sha"
    elif _TAG_LIKE_RE.fullmatch(ref):
        ref_kind = "tag"
    else:
        ref_kind = "branch"
    return {"uses": uses, "ref_kind": ref_kind, "ref": ref}


def _permissions(text: str) -> dict[str, Any]:
    lines = _non_comment_lines(text)
    for index, line in enumerate(lines):
        match = _TOP_PERMISSIONS_RE.match(line)
        if not match:
            continue
        scalar = match.group(1).strip()
        if scalar:
            return {"explicit": True, "form": "scalar", "value": scalar}

        entries: dict[str, str] = {}
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            indent = len(child) - len(child.lstrip())
            if indent == 0:
                break
            entry = re.match(r"^\s+([A-Za-z0-9_-]+):\s*([^#]+?)\s*$", child)
            if entry:
                entries[entry.group(1)] = entry.group(2).strip()
        return {"explicit": True, "form": "mapping", "entries": entries}
    return {"explicit": False}


def inspect_workflow_source(path: str, text: str) -> dict[str, Any]:
    lines = _non_comment_lines(text)
    actions = []
    reusable_workflows = []
    runners: set[str] = set()
    false_green: set[str] = set()
    steps_indent: int | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        indent = len(line) - len(line.lstrip())
        if steps_indent is not None and indent <= steps_indent:
            steps_indent = None
        if re.match(r"^steps:\s*(?:#.*)?$", stripped):
            steps_indent = indent

        action_match = _ACTION_RE.match(line)
        if action_match:
            uses = action_match.group(1).strip()
            if steps_indent is not None and indent > steps_indent:
                actions.append(_classify_action_ref(uses))
            else:
                reusable_workflows.append(_classify_reusable_workflow_ref(uses))

        runner_match = _RUNNER_RE.match(line)
        if runner_match:
            runner = runner_match.group(1).strip().strip("'\"")
            if runner:
                runners.add(runner)

        normalized = line.strip().lower()
        if re.match(r"^continue-on-error:\s*true\s*$", normalized):
            false_green.add("continue-on-error:true")
        if "|| true" in line:
            false_green.add("shell-error-masking")
        if re.search(r"(^|[;&|]\s*)exit\s+0(?:\s|$)", line):
            false_green.add("forced-success-exit")
        if re.search(r"(^|\s)set\s+\+e(?:\s|$)", line):
            false_green.add("shell-errexit-disabled")

    return {
        "path": path,
        "permissions": _permissions(text),
        "actions": actions,
        "reusable_workflows": reusable_workflows,
        "runners": sorted(runners),
        "false_green_patterns": sorted(false_green),
    }


def _subject(evidence: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(evidence) == 1:
        subject = evidence[0].get("subject")
        if isinstance(subject, dict):
            return dict(subject)
    for item in evidence:
        snapshot = item.get("snapshot")
        if isinstance(snapshot, Mapping) and snapshot.get("repository"):
            return {"type": "repository", "identifier": str(snapshot["repository"])}
    return {"type": "repository", "identifier": "unknown"}


def _result(
    control_id: str,
    state: str,
    subject: Mapping[str, Any],
    evidence_ids: Sequence[str],
    *,
    reason: str | None = None,
    candidate: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": dict(subject),
        "evidence_ids": sorted(set(evidence_ids)),
        "candidate_finding_ids": [candidate] if candidate else [],
        "evaluated_at": _now(),
    }
    if reason:
        result["reason"] = reason
    validate_document("control-result.v1", result)
    return result


def _analyses(workflow_evidence: Sequence[Mapping[str, Any]]) -> list[tuple[Mapping[str, Any], dict[str, Any]]]:
    analyses: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
    for item in workflow_evidence:
        observation = item.get("observation")
        if not isinstance(observation, Mapping):
            continue
        path = str(observation.get("path") or item.get("subject", {}).get("identifier") or "unknown")
        text = observation.get("text")
        if not isinstance(text, str):
            continue
        analyses.append((item, inspect_workflow_source(path, text)))
    return analyses


def build_runner_baseline_requests(workflow_evidence: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    runners: set[str] = set()
    for _, analysis in _analyses(workflow_evidence):
        for runner in analysis["runners"]:
            if isinstance(runner, str) and "${{" not in runner:
                runners.add(runner)
    return [
        {
            "type": "baseline_request",
            "subject": f"github-actions/{runner}",
            "identifier": runner,
            "claim": "runner lifecycle",
            "required_authority": "official",
            "reason": "runner lifecycle is time-sensitive",
        }
        for runner in sorted(runners)
    ]


def _evaluate_actionlint_validity(
    workflow_evidence: Sequence[Mapping[str, Any]],
    *,
    specialist_evidence: Sequence[Mapping[str, Any]] | None,
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    source_ids = [
        str(item.get("id")) for item in workflow_evidence if item.get("id")
    ]
    if specialist_evidence is not None:
        specialists = list(specialist_evidence)
        specialist_ids = [
            str(item.get("id")) for item in specialists if item.get("id")
        ]
        validity_ids = sorted(set(source_ids + specialist_ids))
        states: list[str] = []
        for item in specialists:
            observation = item.get("observation")
            if isinstance(observation, Mapping):
                states.append(
                    str(observation.get("actionlint_state", "UNKNOWN_ERROR")).upper()
                )

        if any(state in {"FINDING", "FAIL", "INVALID"} for state in states):
            return _result(
                "CI-STATIC-001",
                "FINDING",
                subject,
                validity_ids,
                reason="actionlint_validation_failed",
                candidate="candidate_CI-STATIC-001_workflow_invalid",
            )
        if any(state in {"UNKNOWN_ERROR", "ERROR"} for state in states):
            return _result(
                "CI-STATIC-001",
                "UNKNOWN_ERROR",
                subject,
                validity_ids,
                reason="actionlint_execution_error",
            )
        if states and all(state == "PASS" for state in states):
            return _result(
                "CI-STATIC-001",
                "PASS",
                subject,
                validity_ids,
            )
        if states and all(state == "UNAVAILABLE" for state in states):
            return _result(
                "CI-STATIC-001",
                "UNAVAILABLE",
                subject,
                validity_ids,
                reason="actionlint_executable_unavailable",
            )
        if states:
            return _result(
                "CI-STATIC-001",
                "INCONCLUSIVE",
                subject,
                validity_ids,
                reason="actionlint_evidence_partial",
            )
        return _result(
            "CI-STATIC-001",
            "INCONCLUSIVE",
            subject,
            validity_ids,
            reason="actionlint_evidence_unavailable",
        )

    evidence_ids = source_ids
    states: list[str] = []
    for item in workflow_evidence:
        observation = item.get("observation")
        if isinstance(observation, Mapping):
            states.append(
                str(observation.get("actionlint_state", "UNAVAILABLE")).upper()
            )
    if any(state in {"FINDING", "FAIL", "INVALID"} for state in states):
        return _result(
            "CI-STATIC-001",
            "FINDING",
            subject,
            evidence_ids,
            reason="actionlint_validation_failed",
            candidate="candidate_CI-STATIC-001_workflow_invalid",
        )
    if states and all(state == "PASS" for state in states):
        return _result("CI-STATIC-001", "PASS", subject, evidence_ids)
    return _result(
        "CI-STATIC-001",
        "INCONCLUSIVE",
        subject,
        evidence_ids,
        reason="actionlint_evidence_unavailable",
    )


def evaluate_ci_static(
    workflow_evidence: Sequence[Mapping[str, Any]],
    *,
    baseline_evidence: Sequence[Mapping[str, Any]] | None = None,
    specialist_evidence: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    items = list(workflow_evidence)
    subject = _subject(items)
    evidence_ids = [str(item.get("id")) for item in items if item.get("id")]
    analyses = _analyses(items)

    # CI-STATIC-001: delegate syntax/semantic validity to specialist evidence.
    validity = _evaluate_actionlint_validity(
        items,
        specialist_evidence=specialist_evidence,
        subject=subject,
    )

    permissions = [analysis["permissions"] for _, analysis in analyses]
    if any(p.get("value") == "write-all" for p in permissions):
        permission_result = _result(
            "CI-STATIC-003", "FINDING", subject, evidence_ids,
            reason="workflow_permissions:write-all",
            candidate="candidate_CI-STATIC-003_write_all",
        )
    elif any(not p.get("explicit") for p in permissions) or not permissions:
        permission_result = _result(
            "CI-STATIC-003", "INCONCLUSIVE", subject, evidence_ids,
            reason="workflow_permissions_not_explicit",
        )
    else:
        granular_write = any(
            p.get("form") == "mapping"
            and any(str(value).lower() == "write" for value in p.get("entries", {}).values())
            for p in permissions
        )
        if granular_write:
            permission_result = _result(
                "CI-STATIC-003", "INCONCLUSIVE", subject, evidence_ids,
                reason="granular_write_permissions_require_context",
            )
        else:
            permission_result = _result("CI-STATIC-003", "PASS", subject, evidence_ids)

    mutable_actions = sorted({
        action["uses"]
        for _, analysis in analyses
        for action in analysis["actions"]
        if action.get("ref_kind") in {"tag", "branch", "unknown"}
    })
    if mutable_actions:
        refs_result = _result(
            "CI-STATIC-004", "FINDING", subject, evidence_ids,
            reason=f"mutable_action_refs:{','.join(mutable_actions)}",
            candidate="candidate_CI-STATIC-004_mutable_action_refs",
        )
    else:
        refs_result = _result("CI-STATIC-004", "PASS", subject, evidence_ids)

    false_green_patterns = sorted({
        pattern
        for _, analysis in analyses
        for pattern in analysis["false_green_patterns"]
    })
    if false_green_patterns:
        false_green_result = _result(
            "CI-STATIC-006", "FINDING", subject, evidence_ids,
            reason=f"false_green_patterns:{','.join(false_green_patterns)}",
            candidate="candidate_CI-STATIC-006_false_green",
        )
    else:
        false_green_result = _result("CI-STATIC-006", "PASS", subject, evidence_ids)

    runners = sorted({
        runner
        for _, analysis in analyses
        for runner in analysis["runners"]
        if isinstance(runner, str) and "${{" not in runner
    })
    baselines = {
        str(item.get("subject")): str(item.get("status", "")).lower()
        for item in (baseline_evidence or [])
        if item.get("claim") == "runner lifecycle"
    }
    risky = []
    missing = []
    risky_statuses = {"retiring", "deprecated", "unsupported", "eol", "removed"}
    for runner in runners:
        status = baselines.get(f"github-actions/{runner}")
        if status is None:
            missing.append(runner)
        elif status in risky_statuses:
            risky.append(f"{runner}={status}")

    if risky:
        runner_result = _result(
            "CI-STATIC-008", "FINDING", subject, evidence_ids,
            reason=f"runner_lifecycle_risk:{','.join(risky)}",
            candidate="candidate_CI-STATIC-008_runner_lifecycle",
        )
    elif missing:
        runner_result = _result(
            "CI-STATIC-008", "INCONCLUSIVE", subject, evidence_ids,
            reason=f"current_runner_baseline_missing:{','.join(missing)}",
        )
    elif runners:
        runner_result = _result("CI-STATIC-008", "PASS", subject, evidence_ids)
    else:
        runner_result = _result(
            "CI-STATIC-008", "INCONCLUSIVE", subject, evidence_ids,
            reason="runner_targets_not_observed",
        )

    return [validity, permission_result, refs_result, false_green_result, runner_result]
