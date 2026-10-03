from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse


ScopeParser = Callable[[Mapping[str, Any]], dict[str, str]]


@dataclass(frozen=True)
class ProviderAdapter:
    provider_id: str
    display_name: str
    adapter_id: str
    app_slugs: tuple[str, ...]
    capabilities: tuple[str, ...]
    scope_parser: ScopeParser

    def matches(self, check: Mapping[str, Any]) -> bool:
        slug = str(check.get("app_slug") or "").lower()
        return slug in self.app_slugs

    def scope(self, check: Mapping[str, Any]) -> dict[str, str]:
        return self.scope_parser(check)




def _details_parts(
    check: Mapping[str, Any],
) -> tuple[str | None, str, dict[str, str]]:
    raw = check.get("details_url")
    if isinstance(raw, str) and raw:
        parsed = urlparse(raw)
        query = parse_qs(parsed.query)
        return (
            parsed.hostname.lower() if parsed.hostname else None,
            parsed.path,
            {
                key: values[0]
                for key, values in query.items()
                if key in {"id", "branch"} and values
            },
        )

    host = check.get("details_host")
    path = check.get("details_path")
    query = check.get("details_query")
    return (
        str(host).lower() if host else None,
        str(path or ""),
        {
            str(key): str(value)
            for key, value in query.items()
            if key in {"id", "branch"} and value is not None
        } if isinstance(query, Mapping) else {},
    )

def _sonar_scope(check: Mapping[str, Any]) -> dict[str, str]:
    host, _, query = _details_parts(check)
    if host not in {"sonarcloud.io", "www.sonarcloud.io"}:
        return {}
    scope: dict[str, str] = {}
    if query.get("id"):
        scope["project_key"] = query["id"]
    if query.get("branch"):
        scope["branch"] = query["branch"]
    return scope


def _socket_scope(check: Mapping[str, Any]) -> dict[str, str]:
    host, path, _ = _details_parts(check)
    if host not in {"socket.dev", "www.socket.dev"}:
        return {}
    parts = [part for part in path.split("/") if part]
    scope: dict[str, str] = {}
    if len(parts) >= 3 and parts[0] == "dashboard" and parts[1] == "org":
        scope["organization"] = parts[2]
    if len(parts) >= 5 and parts[3] in {"sbom", "project", "report"}:
        scope["scope_type"] = parts[3]
        scope["scope_id"] = parts[4]
    return scope



_SONAR = ProviderAdapter(
    provider_id="sonarqube-cloud",
    display_name="SonarQube Cloud",
    adapter_id="sonarqube-cloud/v1",
    app_slugs=("sonarqubecloud",),
    capabilities=("issue_inventory", "quality_gate"),
    scope_parser=_sonar_scope,
)

_SOCKET = ProviderAdapter(
    provider_id="socket",
    display_name="Socket",
    adapter_id="socket/v1",
    app_slugs=("socket-security",),
    capabilities=("dependency_alerts", "dependency_inventory"),
    scope_parser=_socket_scope,
)

_KNOWN = (_SONAR, _SOCKET)


def _generic_scope(check: Mapping[str, Any]) -> dict[str, str]:
    return {}


def resolve_provider_adapter(check: Mapping[str, Any]) -> ProviderAdapter:
    for adapter in _KNOWN:
        if adapter.matches(check):
            return adapter

    slug = str(check.get("app_slug") or "").strip().lower()
    app_id = check.get("app_id")
    provider_id = slug or (
        f"check-app-{app_id}" if app_id is not None else "unknown-check-provider"
    )
    display_name = str(
        check.get("app_name")
        or check.get("app_slug")
        or check.get("name")
        or provider_id
    )
    return ProviderAdapter(
        provider_id=provider_id,
        display_name=display_name,
        adapter_id="generic-github-check/v1",
        app_slugs=(slug,) if slug else (),
        capabilities=(),
        scope_parser=_generic_scope,
    )
