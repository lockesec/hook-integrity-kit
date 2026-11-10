"""Settings that change what hooks do or what an interpreter loads: the ``env`` keys that
steer an interpreter or the kit itself, and the keys that switch hooks off. A change is drift
in ``verify`` and a refusal in ``check-write`` (Write, Edit and MultiEdit, including an edit
that creates the file); unrelated settings stay quiet."""
from __future__ import annotations

import json

import pytest

from conftest import (
    bless, cmd_block, hooks_block, project, project_from_files, run_kit, write_settings,
)
from hook_integrity_kit import manifest as M, writes as W


KIT_ENV = ["DISABLED_HOOKS", "HOOK_PROFILE", "HOOK_KIT_ALLOW_HOOK_EDITS",
           "HOOK_KIT_GATE_CONFIG_OVERRIDE", "hook_kit_anything"]


CTL = ["HOOK_INTEGRITY_MANAGED_DIRS", "HOOK_INTEGRITY_GLOBAL_DIR", "hook_integrity_anything"]


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


def _verify_json(root):
    r = _verify(root, "--json")
    return r.returncode, json.loads(r.stdout)


CONTROL_KEYS = ["disableAllHooks", "allowManagedHooksOnly"]


def _wpayload(fp, tool="Write", **ti):
    return {"hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"file_path": str(fp), **ti}, "cwd": "/work/proj"}


HOOK = cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/h.py")


def _write_payload(root, content):
    return {"tool_name": "Write", "cwd": str(root),
            "tool_input": {"file_path": str(root / ".claude/settings.json"),
                           "content": json.dumps(content)}}


@pytest.mark.parametrize("key", KIT_ENV)
def test_kit_control_variable_is_an_exec_env_key(key):
    assert M.is_exec_env(key)


@pytest.mark.parametrize("key", ["FOO", "MY_HOOK_KIT", "HOOKS_DISABLED"])
def test_benign_env_key_is_not_an_exec_env_key(key):
    assert not M.is_exec_env(key)


@pytest.mark.parametrize("key", KIT_ENV)
def test_kit_control_variable_in_settings_env_is_drift(tmp_path, key):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    bless(root)
    p = root / ".claude/settings.json"
    data = json.loads(p.read_text())
    data["env"] = {key: "check-command,check-write"}
    p.write_text(json.dumps(data))
    res = M.check(root)
    assert res["status"] == "drift" and res["settings_changed"] == [".claude/settings.json"]


def test_benign_env_key_in_settings_is_drift_now_that_the_whole_env_block_is_pinned(tmp_path):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    bless(root)
    p = root / ".claude/settings.json"
    data = json.loads(p.read_text())
    data["env"] = {"FOO": "1"}
    p.write_text(json.dumps(data))
    assert M.check(root)["status"] == "drift"


@pytest.mark.parametrize("key", KIT_ENV)
def test_check_write_refuses_a_kit_control_variable_in_settings_env(tmp_path, key):
    root = project(tmp_path, HOOK)
    verdict, msg = W.decide(_write_payload(root, {"hooks": HOOK, "env": {key: "1"}}), {})
    assert verdict == "deny" and "env" in msg


def test_check_write_refuses_a_benign_env_key_too(tmp_path):
    root = project(tmp_path, HOOK)
    verdict, _ = W.decide(_write_payload(root, {"hooks": HOOK, "env": {"FOO": "1"}}), {})
    assert verdict == "deny"


@pytest.mark.parametrize("key", CTL)
def test_hook_integrity_variable_is_an_exec_env_key(key):
    assert M.is_exec_env(key)


@pytest.mark.parametrize("key", ["HOOK_INTEGRITY", "MY_HOOK_INTEGRITY_X", "INTEGRITY_DIR"])
def test_near_miss_names_are_not_exec_env_keys(key):
    assert not M.is_exec_env(key)


@pytest.mark.parametrize("key", CTL[:2])
def test_check_write_refuses_a_hook_integrity_variable(tmp_path, key):
    root = project(tmp_path, HOOK)
    verdict, msg = W.decide(_write_payload(root, {"hooks": HOOK, "env": {key: "/nowhere"}}), {})
    assert verdict == "deny" and "env" in msg


@pytest.mark.parametrize("key", CTL[:2])
def test_hook_integrity_variable_in_settings_env_is_drift(tmp_path, key):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    bless(root)
    p = root / ".claude/settings.json"
    data = json.loads(p.read_text())
    data["env"] = {key: "/nowhere"}
    p.write_text(json.dumps(data))
    res = M.check(root)
    assert res["status"] == "drift" and res["settings_changed"] == [".claude/settings.json"]


@pytest.mark.parametrize("key", CONTROL_KEYS)
@pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
def test_write_that_switches_hooks_off_is_refused(tmp_path, key, name):
    fp = tmp_path / ".claude" / name
    fp.parent.mkdir()
    fp.write_text(json.dumps({"permissions": {"allow": []}, "hooks": {}}))
    new = json.dumps({"permissions": {"allow": []}, "hooks": {}, key: True})
    v, msg = W.decide(_wpayload(fp, content=new), {})
    assert v == "deny" and key in msg and "claude-settings-hooks" in msg


def test_write_to_the_user_level_settings_is_refused_too(tmp_path):
    fp = tmp_path / "home" / ".claude" / "settings.json"
    fp.parent.mkdir(parents=True)
    new = json.dumps({"disableAllHooks": True})
    assert W.decide(_wpayload(fp, content=new), {})[0] == "deny"


def test_edit_that_adds_the_key_is_refused_and_an_unrelated_edit_passes(tmp_path):
    fp = tmp_path / ".claude" / "settings.json"
    fp.parent.mkdir()
    fp.write_text('{\n  "model": "x",\n  "hooks": {}\n}\n')
    bad = _wpayload(fp, tool="Edit", old_string='"model": "x",',
                    new_string='"model": "x", "disableAllHooks": true,')
    assert W.decide(bad, {})[0] == "deny"
    good = _wpayload(fp, tool="Edit", old_string='"model": "x",',
                     new_string='"model": "y", "language": "en",')
    assert W.decide(good, {})[0] == "allow"
    new = json.dumps({"hooks": {}, "model": "z", "permissions": {"allow": ["Bash(ls:*)"]}})
    assert W.decide(_wpayload(fp, content=new), {})[0] == "allow"


def test_the_surface_hash_moves_with_the_control_keys():
    base = M.settings_hash({"hooks": {}})
    assert M.settings_hash({"hooks": {}, "model": "x"}) == base      # quiet direction
    assert M.settings_hash({"hooks": {}, "disableAllHooks": True}) != base
    assert M.settings_hash({"hooks": {}, "allowManagedHooksOnly": True}) != base


@pytest.mark.parametrize("key", CONTROL_KEYS)
def test_verify_reports_drift_when_a_control_key_appears(tmp_path, key):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n"},
                    hooks_block(".claude/hooks/a.py"))
    assert _bless(root).returncode == 0
    assert _verify(root).returncode == 0
    p = root / ".claude" / "settings.json"
    data = json.loads(p.read_text())
    data["model"] = "unrelated"
    p.write_text(json.dumps(data))
    assert _verify(root).returncode == 0                  # an unrelated key is not drift
    data[key] = True
    p.write_text(json.dumps(data))
    rc, out = _verify_json(root)
    assert rc == 1 and out["settings_changed"] == [".claude/settings.json"]


@pytest.mark.parametrize("key", ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
                                 "PHPRC", "PHP_INI_SCAN_DIR", "LUA_PATH", "LUA_CPATH", "LUA_INIT",
                                 "DOTNET_STARTUP_HOOKS", "GCONV_PATH", "ANTHROPIC_BASE_URL"])
def test_more_interpreter_steering_env_keys_are_pinned(key):
    assert M.is_exec_env(key)
    assert M.settings_hash({"env": {key: "x"}}) != M.settings_hash({})
    assert not M.is_exec_env("MY_TEAM_FLAG")


@pytest.mark.parametrize("name", ["settings.local.json", "settings.json"])
def test_edit_creating_absent_settings_file_with_hook_controls_is_refused(tmp_path, name):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    fp = proj / ".claude" / name
    payload = {"tool_name": "Edit", "cwd": str(proj),
               "tool_input": {"file_path": str(fp), "old_string": "",
                              "new_string": '{"disableAllHooks": true}'}}
    r = run_kit(["check-write"], payload)
    assert r.returncode == 2, r.stderr
    assert not fp.exists()


def test_multiedit_creating_absent_settings_file_is_refused(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    fp = proj / ".claude" / "settings.local.json"
    payload = {"tool_name": "MultiEdit", "cwd": str(proj),
               "tool_input": {"file_path": str(fp), "edits": [
                   {"old_string": "", "new_string": '{"hooks": {"Stop": []}, '},
                   {"old_string": "", "new_string": '"disableAllHooks": true}'}]}}
    assert run_kit(["check-write"], payload).returncode == 2


def test_edit_creating_absent_settings_file_innocent_is_allowed(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    fp = proj / ".claude" / "settings.local.json"
    payload = {"tool_name": "Edit", "cwd": str(proj),
               "tool_input": {"file_path": str(fp), "old_string": "",
                              "new_string": '{"permissions": {"allow": []}}'}}
    assert run_kit(["check-write"], payload).returncode == 0


def test_edit_on_empty_existing_settings_file_still_refused(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    fp = proj / ".claude" / "settings.local.json"
    fp.write_text("")
    payload = {"tool_name": "Edit", "cwd": str(proj),
               "tool_input": {"file_path": str(fp), "old_string": "",
                              "new_string": '{"disableAllHooks": true}'}}
    assert run_kit(["check-write"], payload).returncode == 2


EXEC_ENV = ["PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "BASH_ENV", "ENV",
            "NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
            "pythonpath"]


@pytest.mark.parametrize("key", EXEC_ENV)
def test_an_execution_env_key_is_drift(tmp_path, key):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    bless(root)
    write_settings(root, HOOK)
    data = json.loads((root / ".claude/settings.json").read_text())
    data["env"] = {key: ".claude/cache"}
    (root / ".claude/settings.json").write_text(json.dumps(data))
    res = M.check(root)
    assert res["status"] == "drift" and res["settings_changed"] == [".claude/settings.json"]


@pytest.mark.parametrize("change", [{"model": "other"},
                                    {"permissions": {"allow": ["Bash(git:*)"]}}])
def test_unrelated_settings_are_still_not_drift(tmp_path, change):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    bless(root)
    data = json.loads((root / ".claude/settings.json").read_text())
    data.update(change)
    (root / ".claude/settings.json").write_text(json.dumps(data))
    assert M.check(root)["status"] == "clean"


@pytest.mark.parametrize("key", ["PYTHONPATH", "BASH_ENV", "PATH", "LD_PRELOAD"])
def test_check_write_refuses_an_execution_env_edit(tmp_path, key):
    root = project(tmp_path, HOOK)
    verdict, msg = W.decide(_write_payload(root, {"hooks": HOOK, "env": {key: "x"}}), {})
    assert verdict == "deny" and "env" in msg


@pytest.mark.parametrize("content", [{"hooks": HOOK, "model": "other"},
                                     {"hooks": HOOK, "permissions": {"allow": ["Bash(ls)"]}}])
def test_check_write_allows_unrelated_settings(tmp_path, content):
    root = project(tmp_path, HOOK)
    verdict, _ = W.decide(_write_payload(root, content), {})
    assert verdict == "allow"


def test_check_write_refuses_an_env_edit_through_edit_tool(tmp_path):
    root = project(tmp_path, HOOK, env={"A": "1"})
    payload = {"tool_name": "Edit", "cwd": str(root),
               "tool_input": {"file_path": str(root / ".claude/settings.json"),
                              "old_string": '"A": "1"', "new_string": '"BASH_ENV": "x.sh"'}}
    assert W.decide(payload, {})[0] == "deny"
