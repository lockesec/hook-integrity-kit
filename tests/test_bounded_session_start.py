"""A huge tampered helper must not push the check past the hook timeout in silence: the
file is reported (NOT EVALUABLE, naming it and its size) within the budget, and session-start
prints that, never nothing."""
from __future__ import annotations

import json
import time

from conftest import hooks_block, run_kit, write_settings
from hook_integrity_kit import manifest as M


def _project(tmp_path):
    root = tmp_path / "proj"
    (root / ".claude" / "hooks").mkdir(parents=True)
    (root / ".claude" / "hooks" / "a.py").write_text("import helper\n")
    (root / ".claude" / "hooks" / "helper.py").write_text("X = 1\n")
    write_settings(root, hooks_block(".claude/hooks/a.py"))
    (root / M.BASELINE_REL).write_text(json.dumps(M.build_baseline(root)) + "\n")
    return root


def _bloat(root, mib):
    with open(root / ".claude" / "hooks" / "helper.py", "a") as f:
        f.write("import os\nos.system('echo PWNED')\nx = [" + "(1+2)*3, " * (mib * 1024 * 1024 // 9)
                + "]\n")


def test_oversized_python_file_is_not_evaluable_and_named(tmp_path):
    root = _project(tmp_path)
    _bloat(root, 3)
    t0 = time.monotonic()
    res = M.check(root)
    assert res["status"] == "error", res
    assert "helper.py" in res["error"] and "NOT EVALUABLE" in res["error"]
    assert "MODIFIED" in res["error"]          # the hash comparison still names the tamper
    assert time.monotonic() - t0 < 10


def test_session_start_prints_the_oversized_file(tmp_path):
    root = _project(tmp_path)
    _bloat(root, 3)
    r = run_kit(["session-start", "--root", str(root)], payload={})
    assert r.returncode == 0
    assert "NOT EVALUABLE" in r.stdout and "helper.py" in r.stdout


def test_session_start_deadline_reports_instead_of_silence(tmp_path):
    root = _project(tmp_path)
    # A deadline of 0 seconds stands for "the check ran out of time".
    r = run_kit(["session-start", "--root", str(root)], payload={},
                env={"HOOK_INTEGRITY_SESSION_DEADLINE": "0.001"})
    assert r.returncode == 0
    assert "NOT EVALUABLE" in r.stdout and "did not finish" in r.stdout
