"""Tests run against the source tree (src/ layout) without an install; CI also
runs them against the installed package.

Every fixture is synthetic and built under pytest's tmp_path. No test reads the
real ~/.claude: global coverage is always pointed at a fixture directory."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from hook_integrity_kit import commands as C  # noqa: E402
from hook_integrity_kit import manifest as M  # noqa: E402

# A destructive verb is spelled from fragments so no test file carries a complete command.
RM = "r" + "m"


def run_kit(args, payload=None, env=None, cwd=None, raw=None):
    """Run `python -m hook_integrity_kit ARGS` as a subprocess, the way Claude
    Code runs a hook: JSON on stdin, streams and exit code observed."""
    e = {k: v for k, v in os.environ.items()
         if k not in ("CLAUDE_PROJECT_DIR", "HOOK_PROFILE", "DISABLED_HOOKS",
                      "HOOK_KIT_GATE_CONFIG_OVERRIDE", "HOOK_KIT_ALLOW_HOOK_EDITS",
                      "HOOK_INTEGRITY_GLOBAL_DIR")}
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    # No test may read the machine's real home or managed-settings locations.
    e.setdefault("HOOK_INTEGRITY_MANAGED_DIRS", str(Path(SRC) / "no-such-managed-dir"))
    e.update(env or {})
    body = raw if raw is not None else ("" if payload is None else json.dumps(payload))
    return subprocess.run([sys.executable, "-m", "hook_integrity_kit", *args], input=body,
                          capture_output=True, text=True, timeout=60, env=e, cwd=cwd)


def write_settings(root, hooks_block, permissions=None, name="settings.json"):
    (root / ".claude").mkdir(parents=True, exist_ok=True)
    payload = {"permissions": permissions or {"allow": ["Bash(ls:*)"]},
               "hooks": hooks_block, "env": {}}
    (root / ".claude" / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def hooks_block(*scripts, event="SessionStart"):
    """Exec form (`command` + `args`), as the Claude Code docs describe it."""
    return {event: [{"matcher": "", "hooks": [
        {"type": "command", "command": "python3", "args": ["${CLAUDE_PROJECT_DIR}/" + s]}
        for s in scripts]}]}


def rule_of(cmd, rules=None, ctx=None):
    """Id of the command-guard rule that refuses ``cmd``, or None when it is allowed."""
    r = C.check_command(cmd, rules, ctx)
    return r.id if r else None


def bless(root, **kw):
    """Write a baseline for ``root`` the way ``bless`` does, and return it."""
    base = M.build_baseline(root, **kw)
    path = root / M.BASELINE_REL
    path.write_text(json.dumps(base) + "\n")
    return base


def paths(base):
    return {f["path"]: f for f in base["files"]}


def entry(cmd, htype="command", **extra):
    return dict({"type": htype, "command": cmd}, **extra)


def settings_with(root, *entries, event="PreToolUse"):
    write_settings(root, {event: [{"matcher": "", "hooks": list(entries)}]})


def cmd_block(command, event="SessionStart", htype="command", **extra):
    entry = dict({"type": htype, "command": command}, **extra) if htype == "command" \
        else dict({"type": htype}, **extra)
    return {event: [{"matcher": "", "hooks": [entry]}]}


def project(tmp_path, hooks=None, **settings_extra):
    root = tmp_path / "r"
    (root / ".claude" / "hooks").mkdir(parents=True)
    data = {"hooks": hooks or {}}
    data.update(settings_extra)
    (root / ".claude" / "settings.json").write_text(json.dumps(data))
    return root


def project_from_files(tmp_path, files, settings=None, name="proj"):
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    if settings is not None:
        write_settings(root, settings)
    return root


def not_checked(res):
    return "\n".join(res["not_checked"])


IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
needs_unreadable = pytest.mark.skipif(IS_ROOT, reason="root can read mode-000 files")


@pytest.fixture(autouse=True)
def _isolated_machine(tmp_path_factory, monkeypatch):
    """HOME and the managed-settings locations point at empty fixture dirs, so no
    result depends on what is installed on the machine running the tests."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setenv("HOOK_INTEGRITY_MANAGED_DIRS", str(home / "no-managed"))


@pytest.fixture
def repo(tmp_path):
    """Two registered hooks, one unregistered file, one repo-local plugin."""
    root = tmp_path / "repo"
    hooks = root / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "a.py").write_text("print('a')\n")
    (hooks / "b.py").write_text("print('b')\n")
    (hooks / "unreg.py").write_text("print('unregistered')\n")
    plug = root / ".claude" / "plugins" / "demo" / "hooks"
    plug.mkdir(parents=True)
    (plug / "hooks.json").write_text('{"hooks": {}}\n')
    write_settings(root, hooks_block(".claude/hooks/a.py", ".claude/hooks/b.py"))
    return root
