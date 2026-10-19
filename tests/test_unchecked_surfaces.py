"""Surfaces outside the project are reported NOT CHECKED: the user plugin cache, user-level
settings hooks (unless --include-global), and managed settings files. ``verify`` and ``bless``
print them, ``session-start`` lists them only inside a drift report."""
from __future__ import annotations

import json

from conftest import hooks_block, run_kit, write_settings
from hook_integrity_kit import manifest as M


def _project(tmp_path):
    root = tmp_path / "proj"
    (root / ".claude" / "hooks").mkdir(parents=True)
    (root / ".claude" / "hooks" / "a.py").write_text("print(1)\n")
    write_settings(root, hooks_block(".claude/hooks/a.py"))
    return root


def _bless(root, **kw):
    (root / M.BASELINE_REL).write_text(json.dumps(M.build_baseline(root, **kw)) + "\n")


def _lines(res, needle):
    return [n for n in res["not_checked"] if needle in n]


def _home(tmp_path, hooks=True, cache=True):
    home = tmp_path / "home2"
    g = home / ".claude"
    g.mkdir(parents=True)
    if hooks:
        (g / "settings.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "echo from-user-settings"}]}]}}))
    else:
        (g / "settings.json").write_text(json.dumps({"permissions": {}}))
    if cache:
        d = g / "plugins" / "cache" / "x" / "hooks"
        d.mkdir(parents=True)
        (d / "hooks.json").write_text('{"hooks": {}}')
    return home, g


def test_user_plugin_cache_present_is_named(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path)
    _bless(root)
    res = M.check(root, global_dir=g)
    assert res["status"] == "clean"
    assert _lines(res, "installed plugins"), res["not_checked"]


def test_no_plugin_cache_no_line(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path, cache=False)
    _bless(root)
    assert _lines(M.check(root, global_dir=g), "installed plugins") == []


def test_user_settings_hooks_without_include_global_are_named(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path, cache=False)
    _bless(root)
    res = M.check(root, global_dir=g)
    assert _lines(res, "user-level hooks"), res["not_checked"]


def test_user_settings_hooks_with_include_global_are_covered_not_listed(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path, cache=False)
    _bless(root, include_global=True, global_dir=g)
    res = M.check(root, global_dir=g)
    assert _lines(res, "user-level hooks") == []
    assert res["global_registration_count"] == 1


def test_user_settings_without_hooks_no_line(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path, hooks=False, cache=False)
    _bless(root)
    assert _lines(M.check(root, global_dir=g), "user-level hooks") == []


def test_absent_user_dir_no_lines(tmp_path):
    root = _project(tmp_path)
    _bless(root)
    res = M.check(root, global_dir=tmp_path / "nowhere")
    assert res["not_checked"] == []


def test_managed_settings_present_is_named(tmp_path, monkeypatch):
    root = _project(tmp_path)
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "managed-settings.json").write_text(json.dumps({"hooks": {}}))
    monkeypatch.setenv("HOOK_INTEGRITY_MANAGED_DIRS", str(managed))
    _bless(root)
    res = M.check(root, global_dir=tmp_path / "nowhere")
    assert _lines(res, "managed"), res["not_checked"]


def test_managed_dropin_directory_is_named(tmp_path, monkeypatch):
    root = _project(tmp_path)
    managed = tmp_path / "managed"
    (managed / "managed-settings.d").mkdir(parents=True)
    (managed / "managed-settings.d" / "10-x.json").write_text("{}")
    monkeypatch.setenv("HOOK_INTEGRITY_MANAGED_DIRS", str(managed))
    _bless(root)
    assert _lines(M.check(root, global_dir=tmp_path / "nowhere"), "managed")


def test_no_managed_settings_no_line(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.setenv("HOOK_INTEGRITY_MANAGED_DIRS", str(tmp_path / "empty"))
    _bless(root)
    assert _lines(M.check(root, global_dir=tmp_path / "nowhere"), "managed") == []


def test_cli_reports_unchecked_surfaces_end_to_end(tmp_path):
    """Fake HOME with a user-settings hook and a plugin cache: bless, verify and
    verify --json used to exit 0 with an empty not_checked."""
    root = _project(tmp_path)
    home, g = _home(tmp_path)
    env = {"HOME": str(home)}
    assert run_kit(["bless", "--root", str(root)], env=env).returncode == 0
    res = run_kit(["verify", "--root", str(root)], env=env)
    assert res.returncode == 0
    assert "NOT CHECKED: installed plugins" in res.stdout
    assert "NOT CHECKED: user-level hooks" in res.stdout
    js = json.loads(run_kit(["verify", "--root", str(root), "--json"], env=env).stdout)
    assert len(js["not_checked"]) == 2, js["not_checked"]


def test_session_start_stays_quiet_on_a_clean_surface_and_lists_them_on_drift(tmp_path):
    """Documented: session-start prints the NOT CHECKED list inside a drift report,
    not on every clean start (that would be a line in the model's context every session)."""
    root = _project(tmp_path)
    home, g = _home(tmp_path)
    env = {"HOME": str(home)}
    run_kit(["bless", "--root", str(root)], env=env)
    quiet = run_kit(["session-start", "--root", str(root)], env=env, raw="")
    assert quiet.returncode == 0 and quiet.stdout.strip() == ""
    (root / ".claude" / "hooks" / "a.py").write_text("print(2)\n")
    loud = run_kit(["session-start", "--root", str(root)], env=env, raw="")
    assert "DRIFT" in loud.stdout and "installed plugins" in loud.stdout


def test_bless_names_them_too(tmp_path):
    root = _project(tmp_path)
    home, g = _home(tmp_path)
    res = run_kit(["bless", "--root", str(root)], env={"HOME": str(home)})
    assert "NOT CHECKED" in res.stdout and "installed plugins" in res.stdout
