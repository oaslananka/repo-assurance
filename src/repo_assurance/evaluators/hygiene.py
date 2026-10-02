from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from repo_assurance.core.schema import validate_document


_CONTROL_IDS = (
    "HYGIENE-001",
    "HYGIENE-003",
    "HYGIENE-004",
    "HYGIENE-005",
    "HYGIENE-008",
    "HYGIENE-010",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _result(
    control_id: str,
    state: str,
    subject: Mapping[str, Any],
    evidence_ids: Sequence[str],
    *,
    reason: str | None = None,
    candidate: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "schema_version": "control-result/v1",
        "control_id": control_id,
        "state": state,
        "subject": dict(subject),
        "evidence_ids": sorted(set(evidence_ids)),
        "candidate_finding_ids": [candidate] if candidate else [],
        "evaluated_at": _now(),
    }
    if reason:
        item["reason"] = reason
    validate_document("control-result.v1", item)
    return item


def _repository_subject(evidence: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    for item in evidence:
        snapshot = item.get("snapshot")
        if isinstance(snapshot, Mapping) and snapshot.get("repository"):
            return {"type": "repository", "identifier": str(snapshot["repository"])}
    return {"type": "repository", "identifier": "unknown"}


def evaluate_hygiene(
    evidence: Sequence[Mapping[str, Any]],
    *,
    default_branch: str,
    now: datetime | None = None,
    stale_after_days: int = 90,
) -> list[dict[str, Any]]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stale_cutoff = current - timedelta(days=stale_after_days)
    repo_subject = _repository_subject(evidence)

    branches = [
        item for item in evidence
        if isinstance(item.get("subject"), Mapping)
        and item["subject"].get("type") == "local_branch"
    ]
    worktrees = [
        item for item in evidence
        if isinstance(item.get("subject"), Mapping)
        and item["subject"].get("type") == "worktree"
    ]
    detached = next((item for item in evidence if item.get("id") == "ev_git_detached_head"), None)

    dirty_branches = {
        str(item.get("observation", {}).get("branch"))
        for item in worktrees
        if isinstance(item.get("observation"), Mapping)
        and item["observation"].get("dirty")
        and item["observation"].get("branch")
    }

    results: list[dict[str, Any]] = []
    preservation_labels: list[str] = []

    # HYGIENE-001 — cleanup candidates require strong integration evidence and no preservation signal.
    cleanup_findings = 0
    for branch in branches:
        observation = branch.get("observation")
        subject = branch.get("subject")
        if not isinstance(observation, Mapping) or not isinstance(subject, Mapping):
            continue
        name = str(observation.get("name", subject.get("identifier", "unknown")))
        if name == default_branch:
            continue
        last_commit = _parse_time(observation.get("last_commit_at"))
        stale = bool(last_commit and last_commit < stale_cutoff)
        integrated = observation.get("integration_state") == "FULLY_INTEGRATED"
        if stale and integrated and name not in dirty_branches:
            cleanup_findings += 1
            results.append(_result(
                "HYGIENE-001", "FINDING", subject, [str(branch.get("id"))],
                reason=f"cleanup_candidate:{name}",
                candidate=f"candidate_HYGIENE-001_{name}_cleanup",
            ))
    if not cleanup_findings:
        results.append(_result("HYGIENE-001", "PASS", repo_subject, []))

    # HYGIENE-003 — local branch without upstream is only material when work exists only locally.
    local_only_findings = 0
    for branch in branches:
        observation = branch.get("observation")
        subject = branch.get("subject")
        if not isinstance(observation, Mapping) or not isinstance(subject, Mapping):
            continue
        name = str(observation.get("name", subject.get("identifier", "unknown")))
        if name == default_branch or observation.get("upstream"):
            continue
        ahead = int(observation.get("ahead_of_target") or 0)
        if ahead > 0:
            local_only_findings += 1
            preservation_labels.append(name)
            results.append(_result(
                "HYGIENE-003", "FINDING", subject, [str(branch.get("id"))],
                reason=f"preservation_risk:{name}:local_branch_without_upstream_unique_commits={ahead}",
                candidate=f"candidate_HYGIENE-003_{name}_local_only",
            ))
    if not local_only_findings:
        results.append(_result("HYGIENE-003", "PASS", repo_subject, []))

    # HYGIENE-004 — a configured upstream that is gone plus local unique commits is preservation-first.
    gone_findings = 0
    for branch in branches:
        observation = branch.get("observation")
        subject = branch.get("subject")
        if not isinstance(observation, Mapping) or not isinstance(subject, Mapping):
            continue
        name = str(observation.get("name", subject.get("identifier", "unknown")))
        ahead = int(observation.get("ahead_of_target") or 0)
        if observation.get("upstream_gone") and ahead > 0:
            gone_findings += 1
            preservation_labels.append(name)
            results.append(_result(
                "HYGIENE-004", "FINDING", subject, [str(branch.get("id"))],
                reason=f"preservation_risk:{name}:remote_deleted_local_unique_work",
                candidate=f"candidate_HYGIENE-004_{name}_remote_deleted",
            ))
    if not gone_findings:
        results.append(_result("HYGIENE-004", "PASS", repo_subject, []))

    # HYGIENE-005 — any dirty secondary worktree is preservation-first, regardless of branch age.
    dirty_findings = 0
    for worktree in worktrees:
        observation = worktree.get("observation")
        subject = worktree.get("subject")
        if not isinstance(observation, Mapping) or not isinstance(subject, Mapping):
            continue
        if observation.get("dirty"):
            dirty_findings += 1
            label = str(observation.get("branch") or observation.get("path") or subject.get("identifier"))
            preservation_labels.append(label)
            results.append(_result(
                "HYGIENE-005", "FINDING", subject, [str(worktree.get("id"))],
                reason=f"preserve_first:dirty_worktree:{subject.get('identifier')}",
                candidate=f"candidate_HYGIENE-005_{dirty_findings}_dirty_worktree",
            ))
    if not dirty_findings:
        results.append(_result("HYGIENE-005", "PASS", repo_subject, []))

    # HYGIENE-008 — detached HEAD commits not reachable from the target must be preserved.
    if detached and isinstance(detached.get("observation"), Mapping):
        observation = detached["observation"]
        ahead = int(observation.get("ahead_of_target") or 0)
        if ahead > 0:
            sha = str(observation.get("sha", detached.get("subject", {}).get("identifier", "unknown")))
            preservation_labels.append(f"detached:{sha[:12]}")
            results.append(_result(
                "HYGIENE-008", "FINDING", detached.get("subject", repo_subject), [str(detached.get("id"))],
                reason=f"preservation_risk:detached_head_unique_commits:{ahead}",
                candidate="candidate_HYGIENE-008_detached_unique_work",
            ))
        else:
            results.append(_result("HYGIENE-008", "PASS", repo_subject, [str(detached.get("id"))]))
    else:
        results.append(_result("HYGIENE-008", "PASS", repo_subject, []))

    unique_labels = sorted(set(preservation_labels))
    if unique_labels:
        results.append(_result(
            "HYGIENE-010", "FINDING", repo_subject,
            [str(item.get("id")) for item in evidence if item.get("id")],
            reason=f"lost_work_risk:{','.join(unique_labels)}",
            candidate="candidate_HYGIENE-010_lost_work",
        ))
    else:
        results.append(_result("HYGIENE-010", "PASS", repo_subject, []))

    return results
