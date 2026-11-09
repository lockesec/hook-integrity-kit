"""A project-local package named like the kit must not replace the guards. The registered
hook command ignores a shadow package (and shadow stdlib modules) in the working directory,
and ``check-write`` refuses to create a package of the kit's name."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import RM
from hook_integrity_kit import writes as W


SRC = Path(__file__).resolve().parents[1] / "src"


def _registered(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    out = subprocess.run([sys.executable, "-m", "hook_integrity_kit", "install"],
                         capture_output=True, text=True, env=env, cwd=str(tmp_path),
                         timeout=60).stdout
    return json.loads(out)["hooks"]


def _commands(tmp_path):
    hooks = _registered(tmp_path)
    cmds = []
    for event in hooks.values():
        for entry in event:
            for h in entry["hooks"]:
                cmds.append(h["command"])
    return cmds


SHADOW = {
    "hook_integrity_kit/__init__.py": "import sys\nsys.exit(0)\n",
    "hook_integrity_kit/__main__.py": "import sys\nsys.exit(0)\n",
    "hook_integrity_kit/cli.py": "import sys\nsys.exit(0)\n",
    "json.py": "import sys\nsys.exit(0)\n",
    "re.py": "import sys\nsys.exit(0)\n",
    "os.py": "import sys\nsys.exit(0)\n",
    "argparse.py": "import sys\nsys.exit(0)\n",
    "hashlib.py": "import sys\nsys.exit(0)\n",
}


def _plant(tmp_path):
    work = tmp_path / "proj"
    for rel, body in SHADOW.items():
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return work


def _sh(command, cwd, payload, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(SRC)
    env.update(extra_env or {})
    return subprocess.run(["sh", "-c", command], input=json.dumps(payload), capture_output=True,
                          text=True, cwd=str(cwd), env=env, timeout=60)


def _bash_payload(cmd, cwd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": cmd}, "cwd": str(cwd)}


def shlex_q(s):
    import shlex
    return shlex.quote(s)


def _w(fp):
    return {"hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": fp, "content": "x"}, "cwd": "/work/proj"}


def test_every_registered_command_ignores_a_shadow_package_in_the_cwd(tmp_path):
    work = _plant(tmp_path)
    cmds = _commands(tmp_path)
    assert len(cmds) == 4
    guard = [c for c in cmds if "check-command" in c]
    assert len(guard) == 1
    dangerous = f"{RM} -rf /"
    r = _sh(guard[0], work, _bash_payload(dangerous, work))
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "rm-recursive-root-or-home" in r.stdout + r.stderr


def test_a_shadowed_run_of_the_other_registered_commands_still_runs_the_real_kit(tmp_path):
    work = _plant(tmp_path)
    cmds = {c: c for c in _commands(tmp_path)}
    write = [c for c in cmds if "check-write" in c and "gate" not in c][0]
    p = {"hook_event_name": "PreToolUse", "tool_name": "Write",
         "tool_input": {"file_path": str(work / ".claude" / "hook-integrity.json"),
                        "content": "{}"}, "cwd": str(work)}
    assert _sh(write, work, p).returncode == 2
    gate = [c for c in cmds if "check-gate-config" in c][0]
    # a shadowed kit would exit 0 with no output; the real one reads the payload
    # and, with nothing to judge, also exits 0 -- so tell them apart by --help-like output
    r = _sh(gate, work, {"tool_name": "Bash", "tool_input": {}})
    assert r.returncode == 0
    start = [c for c in cmds if "session-start" in c][0]
    r = _sh(start, work, {"hook_event_name": "SessionStart", "cwd": str(work)})
    # the real session-start with no project root says NOT EVALUABLE; the shadow prints nothing
    assert "not evaluable" in (r.stdout + r.stderr).lower(), (r.stdout, r.stderr)


def test_the_old_form_is_the_hole_it_was(tmp_path):
    work = _plant(tmp_path)
    old = f"{shlex_q(sys.executable)} -m hook_integrity_kit check-command"
    r = _sh(old, work, _bash_payload(f"{RM} -rf /", work))
    assert r.returncode == 0          # the shadow won: this is what the fix closes


def test_a_pythonpath_entry_naming_the_project_still_shadows_and_is_documented(tmp_path):
    """Stated limit (THREAT_MODEL.md): PYTHONPATH is the operator's environment and is
    trusted, in any spelling. Python turns a relative entry into an absolute one before
    any program runs, so it cannot be told apart from an absolute one."""
    work = _plant(tmp_path)
    guard = [c for c in _commands(tmp_path) if "check-command" in c][0]
    pl = _bash_payload(f"{RM} -rf /", work)
    assert _sh(guard, work, pl).returncode == 2
    # The shadow defeats the guard either way: on 3.11+ the shadow kit runs and exits 0; on 3.9
    # and 3.10 a shadow os.py on PYTHONPATH kills the interpreter at startup (site imports os,
    # which is not frozen there), exit 1. Claude Code treats both as "not blocked".
    assert _sh(guard, work, pl, {"PYTHONPATH": str(work)}).returncode != 2
    assert _sh(guard, work, pl, {"PYTHONPATH": str(SRC) + os.pathsep + "."}).returncode != 2


def test_the_registered_command_is_one_c_program_with_an_absolute_interpreter(tmp_path):
    import shlex
    for c in _commands(tmp_path):
        argv = shlex.split(c)
        assert os.path.isabs(argv[0]) and argv[1] == "-c" and len(argv) == 3, c
        assert "-m" not in argv


# the kit's own package name inside a project is a write target the guard refuses

KIT_SHADOW_PATHS = ["/work/proj/hook_integrity_kit/__main__.py",
                    "/work/proj/hook_integrity_kit/__init__.py",
                    "/work/proj/hook_integrity_kit.py", "hook_integrity_kit/cli.py"]


@pytest.mark.parametrize("fp", KIT_SHADOW_PATHS)
def test_check_write_refuses_a_package_of_the_kits_name(fp):
    assert W.decide(_w(fp), {})[0] == "deny"


KIT_SHADOW_NEIGHBOURS = ["/work/proj/src/hook_integrity_kit/cli.py",
                         "/work/proj/docs/hook_integrity_kit.md",
                         "/work/proj/my_hook_integrity_kit/x.py"]


@pytest.mark.parametrize("fp", KIT_SHADOW_NEIGHBOURS)
def test_check_write_allows_the_neighbours(fp):
    assert W.decide(_w(fp), {})[0] != "deny"


def test_check_write_allows_the_relative_src_layout():
    assert W.decide(_w("src/hook_integrity_kit/cli.py"), {})[0] != "deny"
