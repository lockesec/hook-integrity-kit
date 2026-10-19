"""The user-level (~/.claude) surface, warn-only; and the SessionStart hook.

Two properties, pinned in both directions:

* global drift is NAMED (a new registration, a swapped script body, a coverage
  hole), yet it never sets the repo ``status`` and never changes an exit code;
* the session-start hook actually PRINTS it. A suite can pin "X must not gate"
  and never pin "X must still be seen", and the gap between the two reads as
  intentional. So the hook is driven as a subprocess, its real entry point.

Hermetic: every test points global coverage at a fixture directory.

Also here: a vanished global script is named, and ``--include-global`` names unresolved
user hooks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import bless, entry, hooks_block, project_from_files, run_kit, write_settings
from hook_integrity_kit import manifest as M


BANNER = "GLOBAL ~/.claude surface changed"


def write_global(g: Path, hooks: dict) -> None:
    (g / "settings.json").write_text(json.dumps({"hooks": hooks}, indent=2))


def make_global(tmp_path: Path) -> Path:
    g = tmp_path / "dot-claude"
    (g / "hooks").mkdir(parents=True)
    (g / "hooks" / "vendor-a.sh").write_text("#!/bin/sh\necho a\n")
    (g / "hooks" / "vendor-b.sh").write_text("#!/bin/sh\necho b\n")
    write_global(g, {
        "SessionStart": [{"hooks": [{"type": "command", "command": f"sh {g}/hooks/vendor-a.sh"}]}],
        "PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": f"\"{g}/hooks/vendor-b.sh\""}]}],
    })
    return g


@pytest.fixture
def blessed(repo, tmp_path):
    g = make_global(tmp_path)
    r = run_kit(["bless", "--root", str(repo), "--include-global", "--global-dir", str(g)])
    assert r.returncode == 0, r.stderr
    return repo, g


def session(repo, g=None, extra_env=None):
    env = {"CLAUDE_PROJECT_DIR": str(repo)}
    if g is not None:
        env["HOOK_INTEGRITY_GLOBAL_DIR"] = str(g)
    env.update(extra_env or {})
    return run_kit(["session-start"], payload={"hook_event_name": "SessionStart"}, env=env)


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


# --- module level ---------------------------------------------------------

def test_build_inventories_registrations_and_hashes_scripts(tmp_path):
    sec = M.build_global_section(make_global(tmp_path))
    assert sec["covered"] is True and sec["settings_hooks_sha256"]
    assert len(sec["registrations"]) == 2
    assert len(sec["files"]) == 2 and all(f["sha256"] for f in sec["files"])


def test_quoted_registration_still_resolves(tmp_path):
    """A quoted path keeps its quotes through a whitespace split; unstripped, it
    resolves to nothing and coverage silently drops to zero."""
    sec = M.build_global_section(make_global(tmp_path))
    assert any(f["path"].endswith("vendor-b.sh") for f in sec["files"])


def test_clean_round_trip(tmp_path):
    g = make_global(tmp_path)
    out = M.check_global({"global": M.build_global_section(g)}, g)
    assert out["global_status"] == "clean" and out["global_registration_count"] == 2


def test_new_registration_is_named(tmp_path):
    g = make_global(tmp_path)
    base = {"global": M.build_global_section(g)}
    hooks = json.loads((g / "settings.json").read_text())["hooks"]
    hooks["Stop"] = [{"hooks": [{"type": "command", "command": "curl evil.example"}]}]
    write_global(g, hooks)
    out = M.check_global(base, g)
    assert out["global_status"] == "drift"
    assert any("NEW global hook [Stop]" in c for c in out["global_changes"])


def test_content_swap_under_unchanged_registration_is_named(tmp_path):
    g = make_global(tmp_path)
    base = {"global": M.build_global_section(g)}
    (g / "hooks" / "vendor-a.sh").write_text("#!/bin/sh\necho swapped\n")
    out = M.check_global(base, g)
    assert out["global_status"] == "drift"
    assert any("CONTENT changed" in c for c in out["global_changes"])


def test_pre_coverage_baseline_is_not_covered_not_clean(tmp_path):
    assert M.check_global({"files": []}, make_global(tmp_path))["global_status"] == "not-covered"


def test_opted_out_baseline_reports_off_and_reads_nothing(tmp_path):
    missing = tmp_path / "does-not-exist"
    out = M.check_global({"global": {"covered": False}}, missing)
    assert out["global_status"] == "off"


def test_global_drift_never_drives_repo_status(tmp_path):
    g = make_global(tmp_path)
    base = {"global": M.build_global_section(g)}
    (g / "hooks" / "vendor-a.sh").write_text("changed\n")
    out = M.check_global(base, g)
    assert out["global_status"] == "drift" and "status" not in out


def test_registrations_resolving_to_no_script_are_a_coverage_hole(tmp_path):
    g = make_global(tmp_path)
    base = {"global": M.build_global_section(g)}
    write_global(g, {"Stop": [{"hooks": [{"type": "command",
                                          "command": f"{g}/hooks/does-not-exist"}]}]})
    out = M.check_global(base, g)
    assert out["global_status"] == "drift"
    assert any("CONTENT IS UNCHECKED" in c for c in out["global_changes"])


# --- the session-start hook, as a subprocess ------------------------------

def test_missing_baseline_fails_open_with_one_line(repo):
    r = session(repo)
    assert r.returncode == 0
    assert "NOT EVALUABLE" in r.stdout and "bless" in r.stdout
    assert "DRIFT" not in r.stdout


def test_drift_warns_but_never_blocks(blessed):
    repo, g = blessed
    (repo / ".claude/hooks/a.py").write_text("print('swapped')\n")
    r = session(repo, g)
    assert r.returncode == 0
    assert "HOOK INTEGRITY WARNING" in r.stdout
    assert "MODIFIED" in r.stdout and ".claude/hooks/a.py" in r.stdout
    assert "DRIFT" in r.stderr


def test_clean_is_quiet(blessed):
    repo, g = blessed
    r = session(repo, g)
    assert r.returncode == 0
    assert "WARNING" not in r.stdout and "DRIFT" not in r.stdout and BANNER not in r.stdout


def test_unreadable_baseline_fails_open(blessed):
    repo, g = blessed
    (repo / M.BASELINE_REL).write_text("{not json")
    r = session(repo, g)
    assert r.returncode == 0 and "NOT EVALUABLE" in r.stdout


def test_new_global_registration_reaches_stdout(blessed):
    repo, g = blessed
    hooks = json.loads((g / "settings.json").read_text())["hooks"]
    hooks["PostToolUse"] = [{"hooks": [{"type": "command", "command": f"sh {g}/hooks/vendor-a.sh"}]}]
    write_global(g, hooks)
    r = session(repo, g)
    assert r.returncode == 0
    assert BANNER in r.stdout and "PostToolUse" in r.stdout
    assert r.stderr.strip(), "a human-visible banner is expected on stderr"


def test_global_script_body_swap_reaches_stdout(blessed):
    repo, g = blessed
    (g / "hooks" / "vendor-b.sh").write_text("#!/bin/sh\necho changed\n")
    r = session(repo, g)
    assert BANNER in r.stdout and "CONTENT changed" in r.stdout


def test_global_coverage_hole_reaches_stdout(blessed):
    repo, g = blessed
    write_global(g, {"SessionStart": [{"hooks": [
        {"type": "command", "command": f"{g}/hooks/does-not-exist"}]}]})
    r = session(repo, g)
    assert "CONTENT IS UNCHECKED" in r.stdout


def test_global_drift_does_not_change_verify_exit_code(blessed):
    repo, g = blessed
    (g / "hooks" / "vendor-a.sh").write_text("changed\n")
    r = run_kit(["verify", "--root", str(repo), "--global-dir", str(g)])
    assert r.returncode == 0 and BANNER in r.stdout


def test_session_start_survives_internal_errors(tmp_path):
    r = session(tmp_path / "not-a-project")
    assert r.returncode == 0


def test_a_vanished_global_script_is_named_even_when_others_resolve(tmp_path):
    g = tmp_path / "g"
    (g / "hooks").mkdir(parents=True)
    for n in ("a.sh", "b.sh"):
        (g / "hooks" / n).write_text("echo\n")
    (g / "settings.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
        entry(f"bash {g}/hooks/a.sh"), entry(f"bash {g}/hooks/b.sh")]}]}}))
    root = tmp_path / "r"
    write_settings(root, {})
    bless(root, include_global=True, global_dir=g)
    (g / "hooks" / "b.sh").unlink()
    res = M.check(root, global_dir=g)
    assert res["global_status"] == "drift"
    assert any("GONE" in c and "b.sh" in c for c in res["global_changes"])


def test_bless_include_global_names_unresolved_user_hooks(tmp_path):
    gdir = tmp_path / "g"
    gdir.mkdir()
    (gdir / "settings.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "npx some-tool"}]}]}}))
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n"}, hooks_block(".claude/hooks/a.py"))
    r = _bless(root, "--include-global", "--global-dir", str(gdir))
    assert r.returncode == 0 and "resolve to no readable script" in r.stdout
