"""MCP servers in the baseline: `.mcp.json` is hashed, so a changed server command is drift, and
the project files a stdio server names by path are hashed and followed like hook scripts. What
a server runs from an installed package (npx, uvx) is named NOT CHECKED, not left silent."""
import json

from conftest import bless, not_checked, project

from hook_integrity_kit import manifest as M


def mcp(root, servers):
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))


def test_a_changed_server_command_is_drift(tmp_path):
    root = project(tmp_path)
    mcp(root, {"helper": {"command": "npx", "args": ["-y", "helper-mcp@1.2.3"]}})
    bless(root)
    assert M.check(root)["status"] == "clean"
    mcp(root, {"helper": {"command": "npx", "args": ["-y", "evil-mcp"]}})
    assert ".mcp.json" in M.check(root)["modified"]


def test_a_project_script_a_server_runs_is_hashed_and_its_imports_followed(tmp_path):
    root = project(tmp_path)
    (root / "tools").mkdir()
    (root / "tools" / "server.py").write_text("import helper\n")
    (root / "tools" / "helper.py").write_text("x = 1\n")
    mcp(root, {"local": {"command": "python3", "args": ["tools/server.py"]}})
    bless(root)
    (root / "tools" / "helper.py").write_text("x = 2  # changed\n")
    res = M.check(root)
    assert "tools/helper.py" in res["modified"]
    (root / "tools" / "helper.py").write_text("x = 1\n")
    (root / "tools" / "server.py").write_text("import helper\nprint('changed')\n")
    assert "tools/server.py" in M.check(root)["modified"]


def test_an_installed_package_server_is_named_not_checked(tmp_path):
    root = project(tmp_path)
    mcp(root, {"helper": {"command": "npx", "args": ["-y", "helper-mcp"]},
               "web": {"url": "https://mcp.example.com/sse"}})
    bless(root)
    nc = not_checked(M.check(root))
    assert "helper" in nc and "npx -y helper-mcp" in nc and "pin" in nc
    assert "web" in nc and "remote" in nc


def test_no_mcp_config_means_no_entry(tmp_path):
    root = project(tmp_path)
    bless(root)
    assert ".mcp.json" not in M.current_surface(root)["entries"]
