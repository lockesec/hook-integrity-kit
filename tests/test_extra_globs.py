"""Extra-file globs in the kit config: degenerate or blank globs are named and never end in
a traceback, deep globs are NOT EVALUABLE, a glob matching the baseline excludes it and says
so, and ordinary globs still bless and verify."""
from __future__ import annotations

import json

import pytest

from conftest import hooks_block, project_from_files, run_kit, write_settings
from hook_integrity_kit import manifest as M


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


BAD_GLOBS = [".", "/", "./", "/etc/*", "..", "../*", "../../etc/passwd", "~", "~/x",
             "a/../../b", "./.", "//", "**/../*", "\x00", "a\x00b"]


def _cfg_project(tmp_path, globs, name="proj"):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n", "tools/policy.json": "{}\n",
                               "notes.txt": "n\n"},
                    hooks_block(".claude/hooks/a.py"), name=name)
    (root / ".claude" / "hook-integrity-kit.json").write_text(
        json.dumps({"integrity": {"extra_files": globs}}), encoding="utf-8")
    return root


def _script_project(tmp_path, files, name="proj", script="a.sh"):
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    write_settings(root, {"SessionStart": [{"matcher": "", "hooks": [
        {"type": "command", "command": "bash ${CLAUDE_PROJECT_DIR}/" + script}]}]})
    return root


def _cfg(root, globs):
    (root / ".claude").mkdir(exist_ok=True)
    (root / ".claude" / "hook-integrity-kit.json").write_text(
        json.dumps({"integrity": {"extra_files": globs}}))


@pytest.mark.parametrize("glob", BAD_GLOBS)
def test_degenerate_extra_file_globs_are_named_not_evaluable_never_a_traceback(tmp_path, glob):
    root = _cfg_project(tmp_path, [glob])
    r = _bless(root)
    assert r.returncode == 2, (glob, r.stdout, r.stderr)
    assert "Traceback" not in r.stderr and "Traceback" not in r.stdout
    assert "extra_files" in r.stderr
    assert not (root / ".claude" / "hook-integrity.json").exists()


@pytest.mark.parametrize("glob", BAD_GLOBS)
def test_baseline_with_degenerate_extra_globs_is_not_evaluable_not_a_traceback(tmp_path, glob):
    root = _cfg_project(tmp_path, ["tools/*.json"])
    assert _bless(root).returncode == 0
    bp = root / ".claude" / "hook-integrity.json"
    data = json.loads(bp.read_text())
    data["extra_globs"] = [glob]
    bp.write_text(json.dumps(data))
    for args in ([], ["--json"]):
        v = _verify(root, *args)
        assert v.returncode == 2, (glob, v.stdout, v.stderr)
        assert "Traceback" not in v.stderr + v.stdout


GOOD_GLOBS = ["tools/*.json", "./tools/*.json", "tools/**/*.json", "*.txt", "tools/policy.json"]


@pytest.mark.parametrize("glob", GOOD_GLOBS)
def test_ordinary_extra_file_globs_still_bless_and_verify(tmp_path, glob):
    root = _cfg_project(tmp_path, [glob])
    assert _bless(root).returncode == 0
    assert _verify(root).returncode == 0


def test_fuzz_extra_file_globs_never_traceback(tmp_path):
    import random
    rnd = random.Random(13)
    alphabet = ["/", ".", "..", "*", "**", "?", "[", "]", "a", "tools", "~", " ", "\x00", "{", "\\"]
    for n in range(40):
        g = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 6)))
        root = _cfg_project(tmp_path, [g], name=f"p{n}")
        r = _bless(root)
        assert "Traceback" not in r.stderr + r.stdout, (g, r.stderr)
        assert r.returncode in (0, 2), (g, r.returncode, r.stderr)
        if r.returncode == 0:
            v = _verify(root)
            assert "Traceback" not in v.stderr + v.stdout and v.returncode in (0, 1, 2), g


@pytest.mark.parametrize("glob", ["", "  "])
def test_blank_extra_file_glob_is_dropped_with_a_named_warning(tmp_path, glob):
    root = _cfg_project(tmp_path, [glob])
    r = _bless(root)
    assert r.returncode == 0 and "extra_files[0] ignored" in r.stderr


def test_deep_glob_is_not_evaluable_not_a_traceback(tmp_path, monkeypatch):
    from pathlib import Path
    root = _script_project(tmp_path, {"a.sh": "echo\n"})

    def boom(self, pattern, **kw):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(Path, "glob", boom)
    with pytest.raises(M.NotEvaluable) as e:
        M.extra_files(root, ["a/" * 2000 + "b"])
    assert "NOT EVALUABLE" in str(e.value)
    # and the real glob of that shape never produces a traceback through the CLI
    monkeypatch.undo()
    _cfg(root, ["a/" * 2000 + "b"])
    r = run_kit(["bless", "--root", str(root)])
    assert r.returncode in (0, 2) and "Traceback" not in r.stderr + r.stdout


def test_glob_matching_the_baseline_excludes_it_and_says_so(tmp_path):
    root = _script_project(tmp_path, {"a.sh": "echo\n", "t/x.json": "{}\n"})
    _cfg(root, [".claude/*.json", "t/*.json"])
    assert run_kit(["bless", "--root", str(root)]).returncode == 0
    r = run_kit(["bless", "--root", str(root)])         # now the baseline exists
    assert r.returncode == 0 and "baseline file itself" in r.stdout, r.stdout
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert ".claude/hook-integrity.json" not in {f["path"] for f in base["files"]}
    assert run_kit(["verify", "--root", str(root)]).returncode == 0


def test_glob_matching_nothing_is_named_and_exit_zero(tmp_path):
    root = _script_project(tmp_path, {"a.sh": "echo\n"})
    _cfg(root, ["nothing/*.json"])
    r = run_kit(["bless", "--root", str(root)])
    assert r.returncode == 0 and "0 files matched" in r.stdout, r.stdout
