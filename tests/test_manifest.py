"""The integrity baseline: bless / verify behaviour pins.

Each drift class must be detected, and each non-drift must stay quiet. The quiet
half matters as much: a guard that fires on unrelated changes trains people to
re-bless without looking, which is how a real swap gets blessed.

Also here: bless lists every NOT CHECKED line that verify prints, and bless refuses when a
registered script is missing."""
from __future__ import annotations

import json
import os

import pytest

from conftest import (
    bless, cmd_block, hooks_block, needs_unreadable, paths, project, project_from_files,
    run_kit, write_settings,
)
from hook_integrity_kit import manifest as M
from hook_integrity_kit.cli import main


@pytest.fixture
def importer(tmp_path):
    root = tmp_path / "imp"
    hooks = root / ".claude/hooks"
    hooks.mkdir(parents=True)
    (hooks / "entry.py").write_text("import sys\nfrom live_sub import check\n")
    (hooks / "live_sub.py").write_text("def check():\n    import deeper\n    return deeper.go()\n")
    (hooks / "deeper.py").write_text("def go():\n    return 1\n")
    (hooks / "dormant.py").write_text("# nothing imports this\nX = 1\n")
    write_settings(root, {"PreToolUse": [{"matcher": ".*", "hooks": [
        {"type": "command", "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/entry.py"}]}]})
    return root


def _project_with_many_surfaces(tmp_path):
    root = tmp_path / "p"
    (root / ".claude").mkdir(parents=True)
    (root / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "http", "url": "handler.invalid/x"},
            {"type": "command", "command": "npx some-tool --flag"}]}]},
        "statusLine": {"type": "command", "command": "sh ./status.sh"},
        "apiKeyHelper": "sh ./key.sh",
    }), encoding="utf-8")
    (root / ".mcp.json").write_text("{}", encoding="utf-8")
    (root / ".git").mkdir()
    return root


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


# --- build coverage ------------------------------------------------------

def test_bless_covers_registered_plugin_registration_and_lists_unregistered(repo):
    base = bless(repo)
    p = paths(base)
    assert p[".claude/hooks/a.py"]["events"] == ["SessionStart"]
    assert p[".claude/plugins/demo/hooks/hooks.json"]["events"] == [M.EVENT_PLUGIN_REG]
    assert base["unregistered_on_disk"] == [".claude/hooks/unreg.py"]
    assert all(f["sha256"] for f in base["files"])
    assert set(base["settings_hooks_sha256"]) == {".claude/settings.json",
                                                  ".claude/settings.local.json"}


# --- the drift classes, and the quiet ones -------------------------------

def test_clean_check_passes(repo):
    bless(repo)
    assert M.check(repo)["status"] == "clean"
    assert main(["verify", "--root", str(repo)]) == 0


def test_modified_hook_detected(repo):
    bless(repo)
    (repo / ".claude/hooks/a.py").write_text("import os; os.system('curl evil')\n")
    f = M.check(repo)
    assert f["status"] == "drift" and f["modified"] == [".claude/hooks/a.py"]
    assert main(["verify", "--root", str(repo)]) == 1


def test_added_registered_but_unlisted_detected(repo):
    bless(repo)
    (repo / ".claude/hooks/evil.py").write_text("print('x')\n")
    write_settings(repo, hooks_block(".claude/hooks/a.py", ".claude/hooks/b.py",
                                     ".claude/hooks/evil.py"))
    f = M.check(repo)
    assert f["status"] == "drift"
    assert ".claude/hooks/evil.py" in f["added"]
    assert f["settings_changed"] == [".claude/settings.json"]


def test_removed_file_detected(repo):
    bless(repo)
    (repo / ".claude/hooks/b.py").unlink()
    f = M.check(repo)
    assert f["status"] == "drift" and f["removed"] == [".claude/hooks/b.py"]


def test_settings_hooks_block_change_detected(repo):
    bless(repo)
    block = hooks_block(".claude/hooks/a.py", ".claude/hooks/b.py")
    block["SessionStart"][0]["hooks"][0]["args"].append("--exfil")
    write_settings(repo, block)
    f = M.check(repo)
    assert f["status"] == "drift" and f["settings_changed"]
    assert not (f["modified"] or f["added"] or f["removed"])


def test_unrelated_settings_change_not_flagged(repo):
    bless(repo)
    write_settings(repo, hooks_block(".claude/hooks/a.py", ".claude/hooks/b.py"),
                   permissions={"allow": ["Bash(ls:*)", "Bash(cat:*)"], "deny": ["WebFetch"]})
    f = M.check(repo)
    assert f["status"] == "clean" and not f["settings_changed"]


def test_reformatting_settings_is_not_drift(repo):
    bless(repo)
    s = repo / ".claude/settings.json"
    s.write_text(json.dumps(json.loads(s.read_text()), indent=4, sort_keys=True))
    assert M.check(repo)["status"] == "clean"


def test_new_unregistered_on_disk_is_informational_only(repo):
    bless(repo)
    (repo / ".claude/hooks/new_helper.py").write_text("x = 1\n")
    f = M.check(repo)
    assert f["status"] == "clean"
    assert f["info_new_unregistered"] == [".claude/hooks/new_helper.py"]
    assert "info" in M.render_report(f)


def test_registered_but_missing_script_is_a_finding_not_clean(repo):
    write_settings(repo, hooks_block(".claude/hooks/a.py", ".claude/hooks/ghost.py"))
    base = bless(repo)
    assert paths(base)[".claude/hooks/ghost.py"]["sha256"] is None
    f = M.check(repo)
    assert f["status"] == "drift" and ".claude/hooks/ghost.py" in f["removed"]


# --- settings.local.json -------------------------------------------------

def test_hooks_added_in_settings_local_json_are_drift(repo):
    bless(repo)
    (repo / ".claude/hooks/local.sh").write_text("echo hi\n")
    write_settings(repo, {"PreToolUse": [{"matcher": ".*", "hooks": [
        {"type": "command", "command": "sh ${CLAUDE_PROJECT_DIR}/.claude/hooks/local.sh"}]}]},
        name="settings.local.json")
    f = M.check(repo)
    assert f["status"] == "drift"
    assert f["settings_changed"] == [".claude/settings.local.json"]
    assert ".claude/hooks/local.sh" in f["added"]


def test_settings_local_json_without_hooks_is_not_drift(repo):
    bless(repo)
    write_settings(repo, {}, name="settings.local.json")
    assert M.check(repo)["status"] == "clean"


# --- shell-form registrations and paths outside the project -------------

def test_shell_form_and_relative_script_paths_are_hashed(tmp_path):
    root = tmp_path / "p"
    (root / "tools").mkdir(parents=True)
    (root / "tools/check.sh").write_text("echo ok\n")
    (root / ".claude/hooks").mkdir(parents=True)
    (root / ".claude/hooks/x.py").write_text("pass\n")
    write_settings(root, {"Stop": [{"hooks": [
        {"type": "command", "command": "bash tools/check.sh"},
        {"type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/x.py\""}]}]})
    p = paths(bless(root))
    assert p["tools/check.sh"]["sha256"] and p[".claude/hooks/x.py"]["sha256"]


def test_script_outside_the_project_is_named_not_checked(tmp_path, repo):
    outside = tmp_path / "elsewhere.sh"
    outside.write_text("echo hi\n")
    write_settings(repo, {"Stop": [{"hooks": [{"type": "command", "command": f"sh {outside}"}]}]})
    base = bless(repo)
    assert base["external_unchecked"] == [{"event": "Stop", "path": str(outside)}]
    f = M.check(repo)
    assert f["status"] == "clean"
    assert "NOT CHECKED" in M.render_report(f) and str(outside) in M.render_report(f)


def test_kit_registrations_resolve_to_no_repo_script_and_that_is_fine(repo):
    write_settings(repo, {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "python3 -m hook_integrity_kit check-command"}]}]})
    base = bless(repo)
    assert base["external_unchecked"] == []
    assert M.check(repo)["status"] == "clean"


# --- plugins --------------------------------------------------------------

def test_plugin_registered_script_content_swap_is_detected(repo):
    plug = repo / ".claude/plugins/demo/hooks"
    (plug / "run.py").write_text("print('ok')\n")
    (plug / "hooks.json").write_text(json.dumps({"hooks": {"PostToolUse": [{"hooks": [
        {"type": "command", "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/run.py"}]}]}}))
    base = bless(repo)
    assert paths(base)[".claude/plugins/demo/hooks/run.py"]["events"] == [
        "plugin:demo:PostToolUse"]
    (plug / "run.py").write_text("print('swapped')\n")
    assert M.check(repo)["modified"] == [".claude/plugins/demo/hooks/run.py"]


def test_plugin_hooks_json_edit_is_detected(repo):
    bless(repo)
    (repo / ".claude/plugins/demo/hooks/hooks.json").write_text('{"hooks": {"Stop": []}}\n')
    assert M.check(repo)["modified"] == [".claude/plugins/demo/hooks/hooks.json"]


# --- modules a registered hook imports (ported: combiner coverage) -------

def test_an_imported_helper_is_hashed(importer):
    p = paths(M.build_baseline(importer))
    assert p[".claude/hooks/live_sub.py"]["sha256"]


def test_the_import_walk_is_transitive(importer):
    assert ".claude/hooks/deeper.py" in paths(M.build_baseline(importer))


def test_a_dormant_script_stays_informational(importer):
    base = M.build_baseline(importer)
    assert ".claude/hooks/dormant.py" not in paths(base)
    assert ".claude/hooks/dormant.py" in base["unregistered_on_disk"]


def test_the_label_names_the_importing_hook(importer):
    p = paths(M.build_baseline(importer))
    assert f"{M.EVENT_IMPORTED}:entry" in p[".claude/hooks/live_sub.py"]["events"]


def test_editing_an_imported_helper_turns_verify_red(importer):
    bless(importer)
    assert M.check(importer)["status"] == "clean"
    v = importer / ".claude/hooks/live_sub.py"
    v.write_text(v.read_text() + "\n# injected\n")
    f = M.check(importer)
    assert f["status"] == "drift" and f["modified"] == [".claude/hooks/live_sub.py"]


def test_editing_a_dormant_script_does_not_turn_verify_red(importer):
    bless(importer)
    d = importer / ".claude/hooks/dormant.py"
    d.write_text(d.read_text() + "Y = 2\n")
    assert M.check(importer)["status"] == "clean"


def test_import_inside_a_string_or_comment_is_not_an_import(tmp_path):
    assert M.imported_module_names("x = 'import os'\n# from sys import path\n") == set()


# --- kit config, extra files, the kit's own code -------------------------

def test_kit_config_is_hashed_and_its_edit_is_drift(repo):
    cfg = repo / ".claude/hook-integrity-kit.json"
    cfg.write_text('{"commands": {"disable": []}}')
    bless(repo)
    cfg.write_text('{"commands": {"disable": ["rm-recursive-root-or-home"]}}')
    assert M.check(repo)["modified"] == [".claude/hook-integrity-kit.json"]


def test_extra_file_globs_are_covered(repo):
    (repo / "policy").mkdir()
    (repo / "policy/a.json").write_text("{}")
    bless(repo, extra_globs=["policy/*.json"])
    (repo / "policy/a.json").write_text('{"weakened": true}')
    assert M.check(repo)["modified"] == ["policy/a.json"]


def test_a_changed_kit_is_drift(repo, monkeypatch):
    bless(repo)
    real = M.kit_self_files()
    monkeypatch.setattr(M, "kit_self_files",
                        lambda: {**real, "hook_integrity_kit/commands.py": "0" * 64})
    f = M.check(repo)
    assert f["status"] == "drift" and f["kit_changed"] == ["hook_integrity_kit/commands.py"]


# --- not evaluable is never clean ----------------------------------------

def test_no_baseline_is_not_evaluable(repo):
    assert M.check(repo)["status"] == "no-baseline"
    assert main(["verify", "--root", str(repo)]) == 2


def test_unreadable_baseline_is_not_evaluable(repo):
    bless(repo)
    (repo / M.BASELINE_REL).write_text("{not json")
    assert M.check(repo)["status"] == "error"
    assert main(["verify", "--root", str(repo)]) == 2


def test_unreadable_settings_is_not_evaluable(repo):
    bless(repo)
    (repo / ".claude/settings.json").write_text("{broken")
    assert main(["verify", "--root", str(repo)]) == 2
    assert main(["bless", "--root", str(repo)]) == 2


def test_usage_error_is_64():
    assert main(["verify", "--no-such-flag"]) == 64
    assert main([]) == 64


def test_bless_prints_every_not_checked_line_verify_prints(tmp_path):
    from conftest import run_kit
    root = _project_with_many_surfaces(tmp_path)
    b = run_kit(["bless", "--root", str(root)], cwd=str(root))
    assert b.returncode == 0, b.stderr
    v = run_kit(["verify", "--root", str(root), "--json"], cwd=str(root))
    findings = json.loads(v.stdout)
    notes = findings["not_checked"]
    assert len(notes) >= 4, notes                     # the fixture really has surfaces
    missing = [n for n in notes if n not in b.stdout]
    assert not missing, missing


def test_bless_refuses_when_a_registered_script_is_missing(tmp_path):
    root = project_from_files(tmp_path, {}, hooks_block(".claude/hooks/gone.py"))
    r = _bless(root)
    assert r.returncode == 2 and "gone.py" in r.stderr and "MISSING" in r.stderr
    assert not (root / ".claude" / "hook-integrity.json").exists()


def test_bless_allow_missing_writes_it_and_says_so(tmp_path):
    root = project_from_files(tmp_path, {}, hooks_block(".claude/hooks/gone.py"))
    r = _bless(root, "--allow-missing")
    assert r.returncode == 0 and "MISSING" in r.stdout
    assert (root / ".claude" / "hook-integrity.json").is_file()
    assert _verify(root).returncode == 1                  # still a finding


@needs_unreadable
def test_an_unreadable_listed_file_is_not_evaluable_not_a_traceback(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/a.py"))
    (root / ".claude/hooks/a.py").write_text("x = 1\n")
    bless(root)
    write_settings(root, {})                      # no longer registered
    os.chmod(root / ".claude/hooks/a.py", 0)
    try:
        r = run_kit(["verify", "--root", str(root)])
        assert r.returncode == 2 and "Traceback" not in r.stderr, r.stderr
    finally:
        os.chmod(root / ".claude/hooks/a.py", 0o644)
