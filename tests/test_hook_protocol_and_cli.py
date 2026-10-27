"""The guards as Claude Code runs them: JSON on stdin, streams and exit code out.

Pins the documented PreToolUse contract (https://code.claude.com/docs/en/hooks):
a block is exit 2 with a structured ``permissionDecision: "deny"`` on stdout AND
the reason on stderr; a nudge is exit 0 with ``additionalContext``; a benign call
is silent on both streams. The silent control matters: without it, "stderr is
non-empty" could pass because a hook chatters on every call.

Also here: fail-closed payload reading (undecodable, over-deep, closed stdin, any locale),
the pure-JSON install output, a missing --root, and error text that never advises switching
the guard off."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys

import pytest

from conftest import run_kit, SRC
from hook_integrity_kit import hookio


DANGER = "git clean -fd"


def bash(cmd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": cmd}, "cwd": "/tmp"}


def _run_bytes(sub, data):
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    for k in ("CLAUDE_PROJECT_DIR", "HOOK_PROFILE", "DISABLED_HOOKS"):
        e.pop(k, None)
    return subprocess.run([sys.executable, "-m", "hook_integrity_kit", sub], input=data,
                          capture_output=True, timeout=60, env=e)


GUARDS = ["check-command", "check-write", "check-gate-config"]


def _env(**extra):
    e = {k: v for k, v in os.environ.items()
         if k not in ("CLAUDE_PROJECT_DIR", "HOOK_PROFILE", "DISABLED_HOOKS",
                      "HOOK_INTEGRITY_GLOBAL_DIR")}
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    e.update(extra)
    return e


def test_block_uses_the_documented_deny_form_and_reaches_stderr():
    r = run_kit(["check-command"], payload=bash(DANGER))
    assert r.returncode == 2
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    assert "git-clean-force-directories" in out["permissionDecisionReason"]
    assert "git-clean-force-directories" in r.stderr


def test_benign_command_is_silent_on_both_streams():
    r = run_kit(["check-command"], payload=bash("echo hello"))
    assert r.returncode == 0 and not r.stdout.strip() and not r.stderr.strip()


def test_nudge_is_exit_zero_with_additional_context():
    p = {"tool_name": "Write", "tool_input": {"file_path": "/p/.claude/hooks/x.sh",
                                              "content": "echo"}}
    r = run_kit(["check-write"], payload=p)
    assert r.returncode == 0, "a nudge must never use the blocking exit code"
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert "permissionDecision" not in out and "bless" in out["additionalContext"]


def test_write_block_reason_reaches_stderr():
    p = {"tool_name": "Write", "tool_input": {"file_path": "/etc/passwd", "content": "x"}}
    r = run_kit(["check-write"], payload=p)
    assert r.returncode == 2 and "system directory" in r.stderr
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("sub", ["check-command", "check-write", "check-gate-config"])
@pytest.mark.parametrize("raw", ["", "null", "[]", "42", "not json"])
def test_small_malformed_payloads_are_allowed(sub, raw):
    assert run_kit([sub], raw=raw).returncode == 0


@pytest.mark.parametrize("sub", ["check-command", "check-write", "check-gate-config"])
def test_oversized_unparseable_payload_is_refused(sub):
    assert run_kit([sub], raw="{" + "x" * (1024 * 1024 + 10)).returncode == 2


def test_large_well_formed_write_is_judged_on_content_not_size():
    p = {"tool_name": "Write", "tool_input": {"file_path": "/p/big.txt",
                                              "content": "a" * (2 * 1024 * 1024)}}
    assert run_kit(["check-write"], payload=p).returncode == 0
    assert run_kit(["check-gate-config"], payload=p).returncode == 0


def test_sql_tool_lane_is_opt_in_by_config(tmp_path):
    cfgp = tmp_path / "cfg.json"
    cfgp.write_text(json.dumps({"commands": {"sql_tools": {"mcp__db__query": "sql"}}}))
    p = {"tool_name": "mcp__db__query", "tool_input": {"sql": "DROP DATABASE app"}}
    assert run_kit(["check-command"], payload=p).returncode == 0
    assert run_kit(["check-command", "--config", str(cfgp)], payload=p).returncode == 2


def test_project_config_is_found_via_claude_project_dir(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "hook-integrity-kit.json").write_text(
        json.dumps({"commands": {"disable": ["git-clean-force-directories"]}}))
    r = run_kit(["check-command"], payload=bash(DANGER),
                env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    assert r.returncode == 0


def test_broken_config_never_weakens_the_defaults(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "hook-integrity-kit.json").write_text("{not json")
    r = run_kit(["check-command"], payload=bash(DANGER),
                env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    assert r.returncode == 2 and "defaults" in r.stderr


def test_install_prints_a_valid_snippet_and_writes_nothing(tmp_path):
    before = sorted(p.name for p in tmp_path.iterdir())
    r = run_kit(["install"], cwd=tmp_path)
    assert r.returncode == 0
    hooks = json.loads(r.stdout)["hooks"]
    assert set(hooks) == {"SessionStart", "PreToolUse"}
    for groups in hooks.values():
        for g in groups:
            for h in g["hooks"]:
                assert h["type"] == "command" and "hook_integrity_kit" in h["command"]
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_install_snippet_makes_every_guard_fail_closed(tmp_path):
    """A PreToolUse hook that times out, crashes or cannot start lets the call
    through unless `onFailure` is "block". The guards must say so; the
    session-start warning (which never blocks by design) must not."""
    r = run_kit(["install"], cwd=tmp_path)
    hooks = json.loads(r.stdout)["hooks"]
    guards = [h for g in hooks["PreToolUse"] for h in g["hooks"]]
    assert len(guards) == 3 and all(h.get("onFailure") == "block" for h in guards)
    assert all("onFailure" not in h for g in hooks["SessionStart"] for h in g["hooks"])


def test_verify_exit_codes_end_to_end(repo):
    assert run_kit(["verify", "--root", str(repo)]).returncode == 2
    assert run_kit(["bless", "--root", str(repo)]).returncode == 0
    assert run_kit(["verify", "--root", str(repo)]).returncode == 0
    (repo / ".claude/hooks/a.py").write_text("print('changed')\n")
    r = run_kit(["verify", "--root", str(repo), "--json"])
    assert r.returncode == 1 and json.loads(r.stdout)["modified"] == [".claude/hooks/a.py"]
    assert run_kit(["verify", "--bogus"]).returncode == 64


def test_bless_prints_what_it_blessed_and_the_changes_since_last_time(repo):
    run_kit(["bless", "--root", str(repo)])
    (repo / ".claude/hooks/b.py").write_text("print('new b')\n")
    r = run_kit(["bless", "--root", str(repo)])
    assert "Changes since the previous baseline" in r.stdout
    assert "MODIFIED   .claude/hooks/b.py" in r.stdout
    assert ".claude/hooks/a.py" in r.stdout


def test_verify_outside_any_project_is_not_evaluable(tmp_path):
    r = run_kit(["verify"], cwd=tmp_path)
    assert r.returncode in (0, 1, 2)
    if not any((p / ".claude").is_dir() or (p / ".git").exists()
               for p in (tmp_path, *tmp_path.parents)):
        assert r.returncode == 2


def test_install_stdout_is_pure_json_and_the_prose_goes_to_stderr(tmp_path):
    r = run_kit(["install"], cwd=tmp_path)
    assert r.returncode == 0
    assert "hooks" in json.loads(r.stdout)           # redirecting stdout yields a valid file
    assert "Merge the JSON" in r.stderr and "bless" in r.stderr


@pytest.mark.parametrize("sub", ["check-command", "check-write", "check-gate-config"])
def test_a_small_undecodable_payload_is_denied_for_the_right_reason(sub):
    r = _run_bytes(sub, b"\xff\xfe{")
    assert r.returncode == 2
    msg = r.stderr.decode()
    assert "UTF-8" in msg and "1 MiB" not in msg


@pytest.mark.parametrize("sub", ["check-command", "check-write", "check-gate-config"])
def test_an_oversized_payload_still_says_it_is_oversized(sub):
    r = run_kit([sub], raw="{" + "x" * (1024 * 1024 + 10))
    assert r.returncode == 2 and "1 MiB" in r.stderr


@pytest.mark.parametrize("sub", ["verify", "bless"])
def test_a_root_that_does_not_exist_is_named_as_such(sub, tmp_path):
    missing = tmp_path / "nope"
    r = run_kit([sub, "--root", str(missing)])
    out = r.stdout + r.stderr
    assert r.returncode == 2
    assert "does not exist" in out and "no baseline yet" not in out


def test_an_internal_error_on_a_guarded_tool_denies(monkeypatch):
    """A crash an input can provoke must not become a bypass."""
    from hook_integrity_kit import cli
    monkeypatch.setattr(cli.hookio, "read_payload",
                        lambda: ({"tool_name": "Bash", "tool_input": {"command": "ls"}}, False))

    def boom(payload, oversized, cfg):
        raise RuntimeError("boom")
    assert cli._guard(type("A", (), {"config": None})(), "check-command", boom) == hookio.EXIT_DENY


def test_the_real_guard_uncrashed_still_allows_a_benign_command():
    assert run_kit(["check-command"],
                   payload={"tool_name": "Bash", "tool_input": {"command": "ls"}}).returncode == 0


def test_an_internal_error_on_an_unguarded_tool_allows(monkeypatch):
    from hook_integrity_kit import cli
    monkeypatch.setattr(cli.hookio, "read_payload",
                        lambda: ({"tool_name": "Read", "tool_input": {}}, False))

    def boom(payload, oversized, cfg):
        raise RuntimeError("boom")
    assert cli._guard(type("A", (), {"config": None})(), "check-command", boom) == hookio.EXIT_ALLOW


def test_input_over_the_ceiling_is_refused_without_reading_it_all(monkeypatch):
    monkeypatch.setattr(hookio, "MAX_INPUT", 100)
    stream = io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "x" * 500}}))
    payload, oversized = hookio.read_payload(stream)
    assert payload is None and oversized
    assert stream.tell() <= 101


@pytest.mark.parametrize("sub", ["check-command", "check-write", "check-gate-config"])
def test_undecodable_stdin_is_denied_with_the_protocol_json(sub):
    r = _run_bytes(sub, b"\xff\xfe{")
    assert r.returncode == 2, r.stderr
    assert b"Traceback" not in r.stderr
    out = json.loads(r.stdout.decode())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_undecodable_stdin_does_not_break_session_start():
    r = _run_bytes("session-start", b"\xff\xfe{")
    assert r.returncode == 0 and b"Traceback" not in r.stderr


def test_utf8_stdin_is_still_judged_normally():
    ok = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo héllo"}})
    assert _run_bytes("check-command", ok.encode("utf-8")).returncode == 0


@pytest.mark.parametrize("guard", GUARDS)
def test_deeply_nested_payload_is_refused_not_a_crash(guard):
    res = run_kit([guard], raw="[" * 200000)
    assert res.returncode == 2, (res.returncode, res.stderr[-300:])
    assert json.loads(res.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("guard", GUARDS)
def test_deeply_nested_tool_input_is_refused(guard):
    raw = '{"tool_name": "Bash", "tool_input": {"command": "ls", "x": ' + "[" * 200000 + "}}"
    assert run_kit([guard], raw=raw).returncode == 2


@pytest.mark.parametrize("guard", GUARDS)
def test_closed_stdin_is_refused_not_a_crash(guard):
    res = subprocess.run(
        ["sh", "-c", f'exec "{sys.executable}" -m hook_integrity_kit {guard} <&-'],
        capture_output=True, text=True, timeout=60, env=_env())
    assert res.returncode == 2, (res.returncode, res.stderr[-300:])


def test_a_disabled_guard_still_allows_when_stdin_is_closed():
    res = subprocess.run(
        ["sh", "-c", f'exec "{sys.executable}" -m hook_integrity_kit check-command <&-'],
        capture_output=True, text=True, timeout=60, env=_env(DISABLED_HOOKS="check-command"))
    assert res.returncode == 0


BAD = b'{"tool_name": "Bash", "tool_input": {"command": "ls \xff\xfe"}}'


@pytest.mark.parametrize("env", [
    {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"},
    {"LC_ALL": "C.UTF-8"},
    {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONIOENCODING": "latin-1"},
])
@pytest.mark.parametrize("guard", GUARDS)
def test_non_utf8_is_refused_under_any_locale(guard, env):
    res = subprocess.run([sys.executable, "-m", "hook_integrity_kit", guard], input=BAD,
                         capture_output=True, timeout=60, env=_env(**env))
    assert res.returncode == 2, (res.returncode, res.stderr[-300:])
    assert b"UTF-8" in res.stdout


def test_valid_utf8_still_allowed_under_the_c_locale():
    payload = {"tool_name": "Bash", "tool_input": {"command": "echo café"}}
    res = subprocess.run([sys.executable, "-m", "hook_integrity_kit", "check-command"],
                         input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                         capture_output=True, timeout=60,
                         env=_env(LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0"))
    assert res.returncode == 0


@pytest.mark.parametrize("cmd", ["rules", "profile"])
def test_a_missing_root_is_exit_2_for_rules_and_profile(cmd, tmp_path):
    missing = tmp_path / "nope"
    res = run_kit([cmd, "--root", str(missing)])
    assert res.returncode == 2
    assert "does not exist" in res.stderr and str(missing) in res.stderr


@pytest.mark.parametrize("cmd", ["rules", "profile"])
def test_an_existing_root_still_works_for_rules_and_profile(cmd, tmp_path):
    assert run_kit([cmd, "--root", str(tmp_path)]).returncode == 0


def test_install_refuses_an_unusable_interpreter(tmp_path):
    assert run_kit(["install", "--python", ""]).returncode == 64
    assert run_kit(["install", "--python", str(tmp_path / "no-such-python")]).returncode == 64
    notexec = tmp_path / "py"
    notexec.write_text("x")
    assert run_kit(["install", "--python", str(notexec)]).returncode == 64
    assert run_kit(["install", "--python", sys.executable]).returncode == 0


def test_an_oserror_inside_a_guard_is_not_called_a_kit_bug(monkeypatch, tmp_path):
    from hook_integrity_kit import cli

    def boom(payload, oversized, cfg):
        raise PermissionError(13, "Permission denied", "/some/file")
    import argparse
    a = argparse.Namespace(config=None)
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(tmp_path)})))
    rc = cli._guard(a, "check-command", boom)
    assert rc == 2


def test_the_error_text_for_an_oserror_names_the_cause(tmp_path):
    import subprocess
    code = ("import sys, json, io\n"
            "from hook_integrity_kit import cli\n"
            "import argparse\n"
            "def boom(p, o, c):\n"
            "    raise PermissionError(13, 'Permission denied', '/some/file')\n"
            "sys.stdin = io.StringIO(json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'ls'}}))\n"
            "sys.exit(cli._guard(argparse.Namespace(config=None), 'check-command', boom))\n")
    env = dict(os.environ, PYTHONPATH=str(__import__("conftest").SRC), HOME=str(tmp_path))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 2
    assert "PermissionError" in r.stderr and "not a kit bug" in r.stderr
    assert "If this is a kit bug" not in r.stderr


def test_internal_error_message_never_advises_disabling_the_guard(monkeypatch, capsys):
    import argparse

    from hook_integrity_kit import cli
    monkeypatch.setattr(cli.hookio, "read_payload",
                        lambda: ({"tool_name": "Bash", "tool_input": {"command": "ls"}}, False))

    def boom(payload, oversized, cfg):
        raise AttributeError("boom")

    rc = cli._guard(argparse.Namespace(config=None), "check-command", boom)
    out = capsys.readouterr()
    assert rc == 2
    assert "DISABLED_HOOKS" not in out.err + out.out and "boom" in out.err + out.out


def test_unreadable_payload_message_never_advises_disabled_hooks(tmp_path):
    r = run_kit(["check-command"], raw="\xff{not json")
    assert "DISABLED_HOOKS" not in r.stdout + r.stderr


def test_read_error_deny_message_never_advises_disabled_hooks(monkeypatch, capsys):
    import argparse

    from hook_integrity_kit import cli

    def boom():
        raise RecursionError("too deep")

    monkeypatch.setattr(cli.hookio, "read_payload", boom)
    rc = cli._guard(argparse.Namespace(config=None), "check-command", lambda *a: 0)
    out = capsys.readouterr()
    assert rc == 2 and "DISABLED_HOOKS" not in out.err + out.out and "could not read" in (
        out.err + out.out)
