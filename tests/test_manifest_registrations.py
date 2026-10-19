"""Where hooks are registered and what the baseline hashes for each registration: settings
and plugin registrations resolved by one rule, plugin.json (hooks path, inline hooks, nested
plugins, MCP servers), agent frontmatter hooks, command-bearing settings keys, and
handlers that are not commands. What cannot be hashed is named NOT CHECKED, never clean."""
from __future__ import annotations

import json
import os

import pytest

from conftest import (
    bless, cmd_block, entry, needs_unreadable, not_checked, paths, project, run_kit,
    settings_with, write_settings,
)
from hook_integrity_kit import manifest as M


def plugin(root, hooks, name="p", base=".claude/plugins"):
    proot = root / base / name
    (proot / "hooks").mkdir(parents=True, exist_ok=True)
    (proot / "hooks" / "hooks.json").write_text(json.dumps({"hooks": hooks}))
    return proot


def _origin_cases():
    for origin in ("settings", "plugin"):
        yield origin, "project_dir", "bash ${CLAUDE_PROJECT_DIR}/tools/x.sh"
        yield origin, "relative", "bash tools/x.sh"
        yield origin, "quoted_var", 'bash "$CLAUDE_PROJECT_DIR"/tools/x.sh'
    yield "plugin", "plugin_root", "bash ${CLAUDE_PLUGIN_ROOT}/x.sh"


def _plugin_json(root, manifest, name="p"):
    proot = root / ".claude/plugins" / name
    (proot / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (proot / ".claude-plugin" / "plugin.json").write_text(json.dumps(manifest))
    return proot


@pytest.mark.parametrize("htype,extra,needle", [
    ("http", {"url": "https://hooks.example.com/check"}, "http handler"),
    ("mcp_tool", {"server": "audit", "tool": "check"}, "mcp_tool handler"),
    ("prompt", {"prompt": "is this safe?"}, "prompt handler"),
    ("agent", {"prompt": "review the call"}, "agent handler"),
])
def test_non_command_handlers_are_named_not_checked(tmp_path, htype, extra, needle):
    root = tmp_path / "r"
    settings_with(root, dict({"type": htype}, **extra))
    bless(root)
    res = M.check(root)
    assert res["status"] == "clean"
    assert any(needle in n for n in res["not_checked"]), res["not_checked"]
    assert "NOT CHECKED" in M.render_report(res)


def test_changing_a_non_command_handler_definition_is_still_drift(tmp_path):
    root = tmp_path / "r"
    settings_with(root, {"type": "http", "url": "https://a.example.com/x"})
    bless(root)
    settings_with(root, {"type": "http", "url": "https://b.example.com/x"})
    assert M.check(root)["status"] == "drift"


def test_a_command_that_runs_no_project_file_is_named(tmp_path):
    root = tmp_path / "r"
    settings_with(root, entry("npx some-audit-tool --json"))
    bless(root)
    assert any("runs no file inside the project" in n for n in M.check(root)["not_checked"])


@pytest.mark.parametrize("rel", [".claude/skills/deploy/SKILL.md", ".claude/agents/reviewer.md",
                                 ".claude/plugins/p/skills/x/SKILL.md",
                                 ".claude/plugins/p/agents/y.md"])
def test_frontmatter_hooks_are_named_not_checked(tmp_path, rel):
    root = tmp_path / "r"
    write_settings(root, {})
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("---\nname: x\nhooks:\n  PreToolUse: []\n---\nbody\n")
    bless(root)
    assert any(rel in n for n in M.check(root)["not_checked"])


def test_frontmatter_without_hooks_and_body_mentions_are_not_reported(tmp_path):
    root = tmp_path / "r"
    write_settings(root, {})
    f = root / ".claude/skills/a/SKILL.md"
    f.parent.mkdir(parents=True)
    f.write_text("---\nname: a\n---\nhooks: this line is in the body\n")
    bless(root)
    assert M.check(root)["not_checked"] == []


@pytest.mark.parametrize("origin,shape,command", list(_origin_cases()))
def test_every_origin_and_shape_hashes_the_file_it_runs(tmp_path, origin, shape, command):
    root = project(tmp_path)
    (root / "tools").mkdir()
    (root / "tools" / "x.sh").write_text("echo ok\n")
    block = cmd_block(command)
    if origin == "settings":
        write_settings(root, block)
        target = root / "tools" / "x.sh"
    else:
        proot = plugin(root, block)
        target = proot / "x.sh" if shape == "plugin_root" else root / "tools" / "x.sh"
        target.write_text("echo ok\n")
    bless(root)
    target.write_text("echo changed\n")
    res = M.check(root)
    assert res["status"] == "drift", (origin, shape, res)


@pytest.mark.parametrize("origin", ["settings", "plugin"])
@pytest.mark.parametrize("block,needle", [
    (cmd_block("npx some-tool"), "runs no file inside the project"),
    (cmd_block("", htype="http", url="https://hooks.example.com/x"), "http handler"),
    (cmd_block("", htype="prompt", prompt="safe?"), "prompt handler"),
])
def test_unhashable_registrations_are_named_for_every_origin(tmp_path, origin, block, needle):
    root = project(tmp_path)
    if origin == "settings":
        write_settings(root, block)
    else:
        plugin(root, block)
    bless(root)
    res = M.check(root)
    assert res["status"] == "clean"
    assert needle in not_checked(res), res["not_checked"]
    if origin == "plugin":
        assert "plugin" in not_checked(res)


def test_absolute_path_outside_project_in_a_plugin_is_named(tmp_path):
    root = project(tmp_path)
    outside = tmp_path / "elsewhere.sh"
    outside.write_text("echo\n")
    plugin(root, cmd_block(f"bash {outside}"))
    bless(root)
    assert any(str(outside) in e for e in M.check(root)["external_unchecked"])


def test_plugin_json_hooks_path_is_followed(tmp_path):
    root = project(tmp_path)
    proot = _plugin_json(root, {"name": "p", "hooks": "./config/hooks.json"})
    (proot / "config").mkdir()
    (proot / "config" / "hooks.json").write_text(
        json.dumps({"hooks": cmd_block("bash ${CLAUDE_PLUGIN_ROOT}/s.sh")}))
    (proot / "s.sh").write_text("echo ok\n")
    base = bless(root)
    assert ".claude/plugins/p/s.sh" in paths(base)
    (proot / "s.sh").write_text("echo changed\n")
    assert M.check(root)["status"] == "drift"


def test_plugin_json_is_hashed_so_inline_hooks_added_later_are_drift(tmp_path):
    root = project(tmp_path)
    _plugin_json(root, {"name": "p"})
    bless(root)
    _plugin_json(root, {"name": "p", "hooks": {"hooks": cmd_block("echo hi")}})
    res = M.check(root)
    assert res["status"] == "drift" and ".claude/plugins/p/.claude-plugin/plugin.json" in res["modified"]


def test_plugin_json_inline_hooks_scripts_are_hashed(tmp_path):
    root = project(tmp_path)
    proot = _plugin_json(root, {"name": "p",
                                "hooks": {"hooks": cmd_block("bash ${CLAUDE_PLUGIN_ROOT}/s.sh")}})
    (proot / "s.sh").write_text("echo ok\n")
    bless(root)
    (proot / "s.sh").write_text("echo changed\n")
    assert M.check(root)["modified"] == [".claude/plugins/p/s.sh"]


def test_nested_marketplace_plugin_is_covered(tmp_path):
    root = project(tmp_path)
    proot = plugin(root, cmd_block("bash ${CLAUDE_PLUGIN_ROOT}/s.sh"), name="inner",
                   base=".claude/plugins/market/plugins")
    (proot / "s.sh").write_text("echo ok\n")
    bless(root)
    (proot / "s.sh").write_text("echo changed\n")
    assert M.check(root)["modified"] == [".claude/plugins/market/plugins/inner/s.sh"]


def test_a_plugin_json_hooks_path_that_is_missing_is_a_finding(tmp_path):
    root = project(tmp_path)
    _plugin_json(root, {"name": "p", "hooks": "./config/hooks.json"})
    base = bless(root)
    assert paths(base)[".claude/plugins/p/config/hooks.json"]["sha256"] is None
    assert M.check(root)["status"] == "drift"


@pytest.mark.parametrize("text", ['{"hooks": {},}', "", "[]", '{"hooks": []}'])
def test_an_unparseable_plugin_hooks_json_is_not_evaluable(tmp_path, text):
    root = project(tmp_path)
    (root / ".claude/plugins/p/hooks").mkdir(parents=True)
    (root / ".claude/plugins/p/hooks/hooks.json").write_text(text)
    r = run_kit(["bless", "--root", str(root)])
    assert r.returncode == 2, r.stdout + r.stderr


@pytest.mark.parametrize("text", ['{"name": "p",}', "", '"just a string"'])
def test_an_unparseable_plugin_json_is_not_evaluable(tmp_path, text):
    root = project(tmp_path)
    bless(root)
    (root / ".claude/plugins/p/.claude-plugin").mkdir(parents=True)
    (root / ".claude/plugins/p/.claude-plugin/plugin.json").write_text(text)
    assert M.check(root)["status"] == "error"


@needs_unreadable
@pytest.mark.parametrize("rel", [".claude/plugins/p/hooks/hooks.json",
                                 ".claude/plugins/p/.claude-plugin/plugin.json"])
def test_an_unreadable_plugin_registration_is_not_evaluable(tmp_path, rel):
    root = project(tmp_path)
    f = root / rel
    f.parent.mkdir(parents=True)
    f.write_text('{"hooks": {}}' if rel.endswith("hooks.json") else '{"name": "p"}')
    bless(root)
    os.chmod(f, 0)
    try:
        assert M.check(root)["status"] == "error"
    finally:
        os.chmod(f, 0o644)


def test_an_unparseable_plugin_hooks_json_after_bless_is_not_evaluable(tmp_path):
    root = project(tmp_path)
    plugin(root, cmd_block("bash ${CLAUDE_PLUGIN_ROOT}/s.sh"))
    bless(root)
    (root / ".claude/plugins/p/hooks/hooks.json").write_text('{"hooks": {},}')
    r = run_kit(["verify", "--root", str(root)])
    assert r.returncode == 2 and "NOT EVALUABLE" in r.stdout


@pytest.mark.parametrize("extra,needle", [
    ({"statusLine": {"type": "command", "command": "bash s.sh"}}, "statusLine"),
    ({"apiKeyHelper": "bash key.sh"}, "apiKeyHelper"),
    ({"awsAuthRefresh": "aws sso login"}, "awsAuthRefresh"),
])
def test_command_bearing_settings_keys_are_named(tmp_path, extra, needle):
    root = project(tmp_path, **extra)
    bless(root)
    assert needle in not_checked(M.check(root))


@pytest.mark.parametrize("rel", [".mcp.json", ".claude/plugins/p/.mcp.json"])
def test_mcp_server_configs_are_named(tmp_path, rel):
    root = project(tmp_path)
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}))
    bless(root)
    assert rel in not_checked(M.check(root))


def test_plugin_json_mcp_servers_are_named(tmp_path):
    root = project(tmp_path)
    _plugin_json(root, {"name": "p", "mcpServers": {"s": {"command": "x"}}})
    bless(root)
    assert "mcpServers" in not_checked(M.check(root))


@pytest.mark.parametrize("text", [
    '---\n"hooks":\n  Stop: []\n---\nbody\n',
    "---\n'hooks': {}\n---\n",
    "\ufeff---\nhooks:\n  Stop: []\n---\n",
    "---\n{name: x, hooks: {Stop: []}}\n---\n",
    '---\nd: "' + "a" * 21000 + '"\nhooks:\n  Stop: []\n---\n',
    "---\r\nhooks:\r\n  Stop: []\r\n---\r\n",
])
def test_frontmatter_hook_shapes_are_named(tmp_path, text):
    root = project(tmp_path)
    f = root / ".claude/skills/s/SKILL.md"
    f.parent.mkdir(parents=True)
    with open(f, "w", encoding="utf-8", newline="") as fh:     # Path.write_text has no newline= on 3.9
        fh.write(text)
    assert M.frontmatter_hook_files(root) == [".claude/skills/s/SKILL.md"]


@pytest.mark.parametrize("rel", [".claude/plugins/m/plugins/i/skills/s/SKILL.md",
                                 ".claude/plugins/m/plugins/i/agents/a.md"])
def test_frontmatter_in_nested_plugins_is_named(tmp_path, rel):
    root = project(tmp_path)
    f = root / rel
    f.parent.mkdir(parents=True)
    f.write_text("---\nhooks:\n  Stop: []\n---\n")
    assert M.frontmatter_hook_files(root) == [rel]


def test_frontmatter_body_mention_is_still_not_reported(tmp_path):
    root = project(tmp_path)
    f = root / ".claude/skills/s/SKILL.md"
    f.parent.mkdir(parents=True)
    f.write_text("---\nname: s\ndescription: explains git hooks\n---\nhooks: in the body\n")
    assert M.frontmatter_hook_files(root) == []
