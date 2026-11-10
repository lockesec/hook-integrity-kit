"""The whole settings ``env`` block is pinned, not a list of key names. A name list misses keys
that steer a tool nobody listed (OPENSSL_CONF, PIP_INDEX_URL, ANTHROPIC_CUSTOM_HEADERS, ...):
adding, changing or removing ANY env key is drift in ``verify``, a refusal in ``check-write``
and a listed row in ``audit``. The old name list decides only which rows ``audit`` flags."""
from __future__ import annotations

import json

import pytest

from conftest import bless, cmd_block, project, run_kit
from hook_integrity_kit import cli, manifest as M, writes as W

HOOK = cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/h.py")

#: keys no name list in this kit has ever named
UNLISTED = [("OPENSSL_CONF", "/tmp/evil.cnf"),
            ("ANTHROPIC_CUSTOM_HEADERS", "X-Route: attacker"),
            ("PIP_INDEX_URL", "https://pypi.attacker.example/simple")]


def _blessed(tmp_path, env=None):
    root = project(tmp_path, HOOK)
    (root / ".claude/hooks/h.py").write_text("print('ok')\n")
    if env is not None:
        _set_env(root, env)
    bless(root)
    return root


def _set_env(root, env):
    p = root / ".claude/settings.json"
    data = json.loads(p.read_text())
    if env is None:
        data.pop("env", None)
    else:
        data["env"] = env
    p.write_text(json.dumps(data))


def _write_payload(root, data):
    return {"tool_name": "Write", "cwd": str(root),
            "tool_input": {"file_path": str(root / ".claude/settings.json"),
                           "content": json.dumps(data)}}


@pytest.mark.parametrize("key,value", UNLISTED)
def test_an_unlisted_env_key_added_is_drift_in_verify(tmp_path, key, value):
    root = _blessed(tmp_path)
    _set_env(root, {key: value})
    r = run_kit(["verify", "--root", str(root)])
    assert r.returncode == 1 and "settings.json" in r.stdout
    assert value not in r.stdout          # values are never printed


@pytest.mark.parametrize("key,value", UNLISTED)
def test_check_write_refuses_an_unlisted_env_key_with_the_hooks_block_unchanged(tmp_path, key, value):
    root = _blessed(tmp_path)
    r = run_kit(["check-write"], _write_payload(root, {"hooks": HOOK, "env": {key: value}}))
    assert r.returncode == 2
    verdict, msg = W.decide(_write_payload(root, {"hooks": HOOK, "env": {key: value}}), {})
    assert verdict == "deny" and "env" in msg and value not in msg


@pytest.mark.parametrize("key,value", UNLISTED)
def test_audit_lists_an_unlisted_env_key(tmp_path, capsys, key, value):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps({"env": {key: value}}))
    cli.main(["audit", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert f"{key}=" in out and "1 item(s)" in out


def test_a_benign_env_change_is_drift_but_audit_does_not_flag_it(tmp_path, capsys):
    root = _blessed(tmp_path, {"NODE_ENV": "development"})
    assert M.check(root)["status"] == "clean"
    _set_env(root, {"NODE_ENV": "production"})
    res = M.check(root)
    assert res["status"] == "drift" and res["settings_changed"] == [".claude/settings.json"]
    cli.main(["audit", "--root", str(root)])
    out = capsys.readouterr().out
    assert "NODE_ENV=production" in out and "0 flagged" in out
    assert "? " in out


def test_a_fresh_clone_with_only_node_env_is_listed_not_flagged(tmp_path, capsys):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps({"env": {"NODE_ENV": "test"}}))
    rc = cli.main(["audit", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0 and "NODE_ENV=test" in out and "1 item(s) run on their own, 0 flagged" in out


@pytest.mark.parametrize("env", [{"NODE_ENV": "test"}, {"OPENSSL_CONF": "/x"}, {"A": "1", "B": "2"}])
def test_removing_env_keys_is_drift(tmp_path, env):
    root = _blessed(tmp_path, env)
    _set_env(root, None)
    assert M.check(root)["status"] == "drift"
    root2 = _blessed(tmp_path / "two", {**env, "EXTRA": "1"})
    _set_env(root2, env)
    assert M.check(root2)["status"] == "drift"


def test_an_unchanged_env_block_stays_clean_whatever_the_key_order(tmp_path):
    root = _blessed(tmp_path, {"A": "1", "B": [1, 2], "C": {"x": 1}})
    _set_env(root, {"C": {"x": 1}, "B": [1, 2], "A": "1"})
    assert M.check(root)["status"] == "clean"


def test_the_pin_holds_a_digest_of_each_value_never_the_value():
    value = "sk" + "-secret-value"    # split, so this file does not trip a leak gate
    pinned = M.pinned_env({"ANTHROPIC_AUTH_TOKEN": value, "NODE_ENV": "x"})
    assert set(pinned) == {"ANTHROPIC_AUTH_TOKEN", "NODE_ENV"}
    assert value not in json.dumps(pinned)
    assert M.pinned_env({"K": "a"}) != M.pinned_env({"K": "b"})
    assert M.pinned_env({}) == {} and M.pinned_env("not a dict") == {}


def test_a_secret_named_env_value_is_not_printed_by_audit(tmp_path, capsys):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps(
        {"env": {"ANTHROPIC_CUSTOM_HEADERS": "Authorization: Bearer sk-abc123", "X_TOKEN": "t0k"}}))
    cli.main(["audit", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert "sk-abc123" not in out and "t0k" not in out and "ANTHROPIC_CUSTOM_HEADERS" in out
