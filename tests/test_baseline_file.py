"""The baseline file itself: a malformed, over-loose, unreadable, symlinked or
unwritable baseline is NOT EVALUABLE with a named cause (never a traceback, never clean),
and bless leaves no temporary file behind."""
from __future__ import annotations

import json
import os
import stat

import pytest

from conftest import (
    bless, entry, hooks_block, project_from_files, run_kit, settings_with, write_settings,
)
from hook_integrity_kit import manifest as M


def _valid(root):
    (root / ".claude/hooks").mkdir(parents=True, exist_ok=True)
    (root / ".claude/hooks/a.py").write_text("print(1)\n")
    settings_with(root, entry("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/a.py"))
    return bless(root)


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


def _blessed_baseline(tmp_path):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n"}, hooks_block(".claude/hooks/a.py"))
    assert _bless(root).returncode == 0
    return root, root / ".claude" / "hook-integrity.json"


def _good_baseline(tmp_path):
    return _blessed_baseline(tmp_path)


@pytest.mark.parametrize("mutate", [
    lambda b: {},
    lambda b: {**b, "version": 99},
    lambda b: {k: v for k, v in b.items() if k != "files"},
    lambda b: {**b, "settings_hooks_sha256": {}},
    lambda b: {**b, "settings_hooks_sha256": {".claude/settings.json": "nope"}},
    lambda b: {**b, "kit": {"files": {}}},
    lambda b: {**b, "files": b["files"] + b["files"]},
    lambda b: {**b, "files": [{**b["files"][0], "sha256": "zz"}]},
    lambda b: {**b, "files": [{"path": 5, "sha256": None, "events": []}]},
    lambda b: {**b, "global": "yes"},
    lambda b: {**b, "extra_globs": "*.py"},
])
def test_a_malformed_baseline_is_not_evaluable(tmp_path, mutate):
    root = tmp_path / "r"
    base = _valid(root)
    (root / M.BASELINE_REL).write_text(json.dumps(mutate(base)))
    res = M.check(root)
    assert res["status"] == "error", res
    assert run_kit(["verify", "--root", str(root)]).returncode == 2


def test_a_valid_baseline_still_checks_clean(tmp_path):
    root = tmp_path / "r"
    _valid(root)
    assert M.check(root)["status"] == "clean"


def test_bless_refuses_a_symlinked_baseline(tmp_path):
    root = tmp_path / "r"
    write_settings(root, {})
    outside = tmp_path / "elsewhere.json"
    outside.write_text("{}")
    (root / M.BASELINE_REL).symlink_to(outside)
    res = run_kit(["bless", "--root", str(root)])
    assert res.returncode == 2 and "symlink" in res.stderr
    assert outside.read_text() == "{}"


def test_bless_leaves_no_temp_file_behind(tmp_path):
    root = tmp_path / "r"
    write_settings(root, {})
    assert run_kit(["bless", "--root", str(root)]).returncode == 0
    assert [p.name for p in (root / ".claude").iterdir() if p.name.endswith(".tmp")] == []
    M.validate_baseline(json.loads((root / M.BASELINE_REL).read_text()))


def test_a_100k_character_baseline_path_is_not_evaluable_with_a_cause(tmp_path):
    root, bp = _blessed_baseline(tmp_path)
    data = json.loads(bp.read_text())
    data["files"][0]["path"] = "a" * 100_000
    bp.write_text(json.dumps(data))
    r = _verify(root)
    assert r.returncode == 2 and "Traceback" not in r.stderr
    assert "NOT EVALUABLE" in r.stdout and "too long" in r.stdout.lower()


@pytest.mark.parametrize("target", ["/root/x.json", "/nonexistent/dir/x.json", "/proc/x/y"])
def test_bless_to_an_unwritable_baseline_path_is_not_evaluable(tmp_path, target):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n"}, hooks_block(".claude/hooks/a.py"))
    r = _bless(root, "--baseline", target)
    assert r.returncode == 2 and "Traceback" not in r.stderr
    assert "bless failed" in r.stderr and target in r.stderr


def test_a_directory_as_the_baseline_names_that_cause(tmp_path):
    root, _ = _blessed_baseline(tmp_path)
    d = tmp_path / "adir"
    d.mkdir()
    b = _bless(root, "--baseline", str(d))
    assert b.returncode == 2 and "directory" in b.stderr
    v = _verify(root, "--baseline", str(d))
    assert v.returncode == 2 and "directory" in v.stdout and "no baseline yet" not in v.stdout


def test_an_unreadable_baseline_directory_is_not_evaluable(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read anything")
    root, bp = _blessed_baseline(tmp_path)
    os.chmod(bp.parent, 0)
    try:
        r = _verify(root, "--baseline", str(bp))
        assert r.returncode == 2 and "Traceback" not in r.stderr
    finally:
        os.chmod(bp.parent, stat.S_IRWXU)


@pytest.mark.parametrize("mutate", [
    lambda d: d.__setitem__("generated", None),
    lambda d: d.__setitem__("generated", 5),
    lambda d: d.__setitem__("generated", {}),
    lambda d: d.__setitem__("external_unchecked", [None]),
    lambda d: d.__setitem__("external_unchecked", [{"event": 1, "path": "x"}]),
    lambda d: d["global"].__setitem__("registrations", "x") or d["global"].__setitem__("covered", True),
])
def test_a_baseline_looser_than_its_schema_is_not_evaluable(tmp_path, mutate):
    root, bp = _good_baseline(tmp_path)
    data = json.loads(bp.read_text())
    mutate(data)
    bp.write_text(json.dumps(data))
    r = _verify(root)
    assert r.returncode == 2 and "Traceback" not in r.stderr
