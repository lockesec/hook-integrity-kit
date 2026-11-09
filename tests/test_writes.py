"""check-write: hard blocks, the settings-hooks rule, per-agent scopes, nudges.

Also here: the settings rule is case-insensitive and a ``.git`` file is git internals."""
from __future__ import annotations

import json

import pytest

from hook_integrity_kit import writes as W


def payload(fp, tool="Write", content="x", **extra):
    ti = {"file_path": fp}
    if tool == "Write":
        ti["content"] = content
    ti.update(extra.pop("ti", {}))
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti,
            "cwd": "/work/proj", **extra}


def verdict(p, cfg=None):
    return W.decide(p, cfg or {})[0]


# (rule id, blocked path, benign neighbour)
HARD = [
    ("env-file", "/work/proj/.env", "/work/proj/.env.example"),
    ("env-file", "/work/proj/.env.production", "/work/proj/.envrc.md"),
    ("env-file", "/work/proj/deploy/prod.env", "/work/proj/docs/env.md"),
    ("credentials-json", "/work/proj/credentials.json", "/work/proj/credentials_schema.md"),
    # fixture home paths are assembled from fragments (as attack payloads are) so
    # secret/path scanners run over this repo stay quiet
    ("aws-credentials", "/" + "home/u/.aws/credentials", "/" + "home/u/.aws/config.md"),
    ("ssh-dir", "/" + "home/u/.ssh/config", "/work/proj/docs/ssh-setup.md"),
    ("ssh-private-key", "/work/proj/keys/id_ed25519", "/work/proj/keys/id_ed25519.pub"),
    ("system-dir", "/etc/passwd", "/work/proj/etc/app.conf"),
    ("system-dir", "/usr/bin/evil", "/work/proj/usr/bin/tool"),
    ("system-dir", "/var/log/app.log", "/work/proj/var/log/app.log"),
    ("git-internals", "/work/proj/.git/hooks/pre-commit", "/work/proj/.github/workflows/ci.yml"),
    ("git-internals", "/work/proj/.git/config", "/work/proj/.gitignore"),
    ("kit-baseline", "/work/proj/.claude/hook-integrity.json", "/work/proj/docs/hook-integrity.json"),
    ("kit-config", "/work/proj/.claude/hook-integrity-kit.json", "/work/proj/hook-integrity-kit.json"),
    ("kit-package-shadow", "/work/proj/hook_integrity_kit/__main__.py",
     "/work/proj/src/hook_integrity_kit/cli.py"),
]


@pytest.fixture
def settings(tmp_path):
    p = tmp_path / ".claude" / "settings.json"
    p.parent.mkdir()
    p.write_text(json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}, "hooks": {}}, indent=2))
    return p


HOOK = {"SessionStart": [{"hooks": [{"type": "command", "command": "sh x.sh"}]}]}


SCOPES = {"writes": {"agent_scopes": {
    "researcher": ["notes/**", "/tmp/scratch-*/**"],
    "broken": "not-a-list"}}}


def scoped(fp, agent="researcher", **extra):
    return payload(fp, agent_type=agent, **extra)


def _wpayload(fp, tool="Write", **ti):
    return {"hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"file_path": str(fp), **ti}, "cwd": "/work/proj"}


@pytest.mark.parametrize("rule_id,blocked,benign", HARD)
def test_hard_block_fires_and_neighbour_passes(rule_id, blocked, benign):
    v, msg = W.decide(payload(blocked), {})
    assert v == "deny" and f"rule {rule_id}" in msg
    assert verdict(payload(benign)) == "allow"


def test_every_hard_block_has_a_case():
    assert {c[0] for c in HARD} == {r.id for r in W.HARD_BLOCKS}


def test_non_write_tools_are_ignored():
    assert verdict({"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}}) == "allow"


def test_multiedit_and_notebookedit_are_covered():
    assert verdict(payload("/etc/hosts", tool="MultiEdit", ti={"edits": []})) == "deny"
    assert verdict({"tool_name": "NotebookEdit",
                    "tool_input": {"notebook_path": "/work/proj/.git/x.ipynb"}}) == "deny"


# --- the settings-hooks rule -----------------------------------------------

def test_write_that_adds_a_hook_is_denied(settings):
    new = json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}, "hooks": HOOK})
    v, msg = W.decide(payload(str(settings), content=new), {})
    assert v == "deny" and "claude-settings-hooks" in msg


def test_write_that_changes_only_permissions_is_allowed(settings):
    new = json.dumps({"permissions": {"allow": ["Bash(ls:*)", "Bash(cat:*)"]}, "hooks": {}})
    assert verdict(payload(str(settings), content=new)) == "allow"


def test_edit_that_changes_hooks_is_denied_and_unrelated_edit_is_allowed(settings):
    text = settings.read_text()
    bad = payload(str(settings), tool="Edit", ti={
        "old_string": '"hooks": {}', "new_string": '"hooks": ' + json.dumps(HOOK)})
    assert text.count('"hooks": {}') == 1
    assert verdict(bad) == "deny"
    ok = payload(str(settings), tool="Edit", ti={
        "old_string": '"Bash(ls:*)"', "new_string": '"Bash(ls:*)", "Bash(pwd)"'})
    assert verdict(ok) == "allow"


def test_multiedit_is_applied_in_order(settings):
    p = payload(str(settings), tool="MultiEdit", ti={"edits": [
        {"old_string": '"Bash(ls:*)"', "new_string": '"Bash(ls)"'},
        {"old_string": '"hooks": {}', "new_string": '"hooks": ' + json.dumps(HOOK)}]})
    assert verdict(p) == "deny"


def test_new_settings_file_with_hooks_is_denied(tmp_path):
    fp = tmp_path / ".claude" / "settings.local.json"
    assert verdict(payload(str(fp), content=json.dumps({"hooks": HOOK}))) == "deny"
    assert verdict(payload(str(fp), content=json.dumps({"env": {"A": "1"}}))) == "allow"


def test_unparseable_new_settings_content_fails_closed(settings):
    assert verdict(payload(str(settings), content='{"hooks": ')) == "deny"


def test_settings_named_file_outside_dot_claude_is_not_this_rule(tmp_path):
    fp = tmp_path / "vscode" / "settings.json"
    assert verdict(payload(str(fp), content=json.dumps({"hooks": HOOK}))) == "allow"


def test_operator_override_allows_hook_edits(settings, monkeypatch):
    monkeypatch.setenv(W.HOOK_EDIT_OVERRIDE, "1")
    new = json.dumps({"hooks": HOOK})
    assert verdict(payload(str(settings), content=new)) == "allow"


def test_settings_rule_stays_on_when_a_config_disables_it(settings):
    new = json.dumps({"hooks": HOOK})
    cfg = {"writes": {"disable": ["claude-settings-hooks"]}}
    assert verdict(payload(str(settings), content=new), cfg) == "deny"


def test_the_operator_can_let_a_config_disable_the_settings_rule(settings, monkeypatch):
    monkeypatch.setenv("HOOK_KIT_ALLOW_PROTECTION_OFF", "1")
    new = json.dumps({"hooks": HOOK})
    cfg = {"writes": {"disable": ["claude-settings-hooks"]}}
    assert verdict(payload(str(settings), content=new), cfg) == "allow"


# --- nudges ---------------------------------------------------------------

def test_hook_script_edit_is_a_nudge_not_a_block():
    v, msg = W.decide(payload("/work/proj/.claude/hooks/greet.sh"), {})
    assert v == "nudge" and "bless" in msg


@pytest.mark.parametrize("content,label", [
    ('pass' + 'word = "' + "hunter2" * 2 + '"', "password"),
    ("api_key = '" + "a" * 12 + "'", "API key"),
    ("AKIA" + "ABCDEFGHIJKLMNOP", "AWS"),
    ("token: sk-" + "a1" * 12, "sk-"),
])
def test_secret_shaped_content_is_a_nudge(content, label):
    v, msg = W.decide(payload("/work/proj/app.py", content=content), {})
    assert v == "nudge" and label in msg


def test_ordinary_content_is_silent():
    assert verdict(payload("/work/proj/app.py", content="password = get_secret()\n")) == "allow"


def test_config_extra_block_and_warn():
    cfg = {"writes": {"extra_block": [{"id": "no-migrations", "pattern": r"/migrations/"}],
                      "extra_warn": [{"id": "lockfile", "pattern": r"poetry\.lock$"}]}}
    assert verdict(payload("/work/proj/db/migrations/001.sql"), cfg) == "deny"
    assert verdict(payload("/work/proj/poetry.lock"), cfg) == "nudge"


# --- per-agent write scopes (ported behaviour pins) -----------------------

def test_scoped_agent_in_scope_write_allowed():
    assert verdict(scoped("/work/proj/notes/a.md"), SCOPES) == "allow"


def test_scoped_agent_out_of_scope_write_blocked():
    v, msg = W.decide(scoped("/work/proj/src/app.py"), SCOPES)
    assert v == "deny" and "researcher" in msg


def test_scoped_agent_relative_path_out_of_scope_blocked():
    assert verdict(scoped("src/app.py"), SCOPES) == "deny"


def test_scope_escape_via_dotdot_blocked():
    assert verdict(scoped("/work/proj/notes/../src/app.py"), SCOPES) == "deny"


def test_absolute_glob_scope_allowed():
    assert verdict(scoped("/tmp/scratch-1/out.json"), SCOPES) == "allow"


def test_unscoped_agent_keeps_global_behaviour():
    assert verdict(scoped("/work/proj/src/app.py", agent="coder"), SCOPES) == "allow"


def test_main_session_is_never_scope_blocked():
    assert verdict(payload("/work/proj/src/app.py"), SCOPES) == "allow"


def test_agent_id_without_agent_type_falls_back_to_global_rules():
    assert verdict(payload("/work/proj/src/app.py", agent_id="abc"), SCOPES) == "allow"


def test_hard_blocks_still_apply_inside_scope():
    cfg = {"writes": {"agent_scopes": {"researcher": ["**"]}}}
    assert verdict(scoped("/work/proj/.env"), cfg) == "deny"


def test_malformed_scope_entry_gets_an_empty_scope_and_siblings_enforce():
    scopes = W.load_scopes(SCOPES)
    assert scopes["researcher"] == ["notes/**", "/tmp/scratch-*/**"]
    broken = [a for a, g in scopes.items() if a != "researcher"]
    assert broken and all(scopes[a] == [] for a in broken)


def test_scope_relativizes_against_claude_project_dir(monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "/other/root")
    p = scoped("/other/root/notes/x.md")
    p["cwd"] = "/somewhere/else"
    assert W.check_write_scope(p, W.load_scopes(SCOPES)) == (False, "researcher")


def test_scoped_agent_with_empty_path_fails_closed():
    p = {"tool_name": "Write", "tool_input": {}, "agent_type": "researcher"}
    assert W.check_write_scope(p, W.load_scopes(SCOPES)) == (True, "researcher")


@pytest.mark.parametrize("fp", [".CLAUDE/settings.json", ".claude/Settings.JSON"])
def test_settings_rule_is_case_insensitive(fp):
    assert W.is_settings_file(fp)


def test_git_dot_file_is_git_internals():
    assert W.decide(_wpayload("/work/proj/.git", content="gitdir: /elsewhere"), {})[0] == "deny"
    assert W.decide(_wpayload("/work/proj/sub/.git", content="gitdir: x"), {})[0] == "deny"
    assert W.decide(_wpayload("/work/proj/.gitignore", content="x"), {})[0] == "allow"
    assert W.decide(_wpayload("/work/proj/.github/x.yml", content="x"), {})[0] == "allow"


# ── plugin registrations and .mcp.json are guarded like the settings hooks block ──

HOOKS_JSON = json.dumps({"hooks": {"SessionStart": [{"hooks": [
    {"type": "command", "command": "sh evil.sh"}]}]}})
MCP_JSON = json.dumps({"mcpServers": {"x": {"command": "sh", "args": ["evil.sh"]}}})


@pytest.mark.parametrize("path,content", [
    ("/work/proj/.claude/plugins/x/hooks/hooks.json", HOOKS_JSON),
    ("/work/proj/.claude/plugins/x/.claude-plugin/plugin.json", HOOKS_JSON),
    ("/work/proj/.claude/plugins/x/.claude-plugin/plugin.json", MCP_JSON),
    ("/work/proj/.mcp.json", MCP_JSON),
])
def test_write_that_adds_a_plugin_hook_or_mcp_server_is_denied(path, content):
    assert verdict(payload(path, content=content)) == "deny"


@pytest.mark.parametrize("path", [
    "/work/proj/.claude/plugins/x/.claude-plugin/plugin.json",
    "/work/proj/.mcp.json",
])
def test_write_to_those_files_that_adds_nothing_runnable_is_allowed(path):
    assert verdict(payload(path, content='{"name": "x", "version": "1"}')) == "allow"
