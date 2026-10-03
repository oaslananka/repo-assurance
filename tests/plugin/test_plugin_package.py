from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_plugin_manifest_is_agent_plugins_v1() -> None:
    manifest = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["$schema"] == "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
    assert manifest["name"] == "repo-assurance"
    assert manifest["version"] == "0.2.2"
    interface = manifest["extensions"]["com.openai"]["interface"]
    assert interface["displayName"] == "Repo Assurance"
    assert len(interface["shortDescription"]) <= 30
    assert interface["defaultPrompt"]


def test_mcp_config_launches_local_python_server_from_plugin_root() -> None:
    config = json.loads((ROOT / "mcp.json").read_text(encoding="utf-8"))
    assert config["$schema"] == "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
    server = config["mcpServers"]["repo-assurance"]
    assert server["type"] == "stdio"
    assert server["command"] == "python"
    assert server["args"] == ["-m", "repo_assurance.mcp_server"]
    assert server["cwd"] == "${PLUGIN_ROOT}"
    assert server["env"]["PYTHONPATH"] == "${PLUGIN_ROOT}/src"


def test_plugin_skill_contains_safety_invariants() -> None:
    skill = (ROOT / "skills" / "repository-assurance" / "SKILL.md").read_text(encoding="utf-8")
    assert "name: repository-assurance" in skill
    assert "read-only" in skill.lower()
    assert "unknown" in skill.lower()
    assert "preservation" in skill.lower()
    assert "audit_repository" in skill


def test_mcp_server_registers_only_read_only_tools() -> None:
    source = (ROOT / "src" / "repo_assurance" / "mcp_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {
            "discover_repository",
            "plan_repository_audit",
            "audit_repository",
            "render_audit_report",
        }
    }
    assert function_names == {
        "discover_repository",
        "plan_repository_audit",
        "audit_repository",
        "render_audit_report",
    }
    assert source.count("read_only_hint=True") == 4
    assert "mcp.run()" in source


def test_pyproject_has_plugin_extra() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'plugin = ["mcp>=2,<3"]' in text
