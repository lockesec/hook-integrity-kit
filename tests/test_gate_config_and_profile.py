"""check-gate-config (adapted from ECC's config-protection) and hook profiles.

Also here: the gate config is judged through symlinks, by case, and for new files."""
from __future__ import annotations

import os

import pytest

from conftest import run_kit
from hook_integrity_kit import gateconfig as G, profile as P


def edit(fp):
    return {"tool_name": "Edit", "tool_input": {"file_path": str(fp)}}


@pytest.fixture
def env(monkeypatch):
    def set_(profile=None, disabled=None):
        monkeypatch.delenv("HOOK_PROFILE", raising=False)
        monkeypatch.delenv("DISABLED_HOOKS", raising=False)
        if profile:
            monkeypatch.setenv("HOOK_PROFILE", profile)
        if disabled:
            monkeypatch.setenv("DISABLED_HOOKS", disabled)
    return set_


def gate(p, env=None):
    return run_kit(["check-gate-config"], payload=p, env=env)


CFG = {"profiles": {"tiers": {"lint": "standard", "deep_scan": "strict", "must": "critical"},
                    "always_on": ["must"]}}


def _project(tmp_path):
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "gated.py").write_text("from hook_integrity_kit.profile import should_run\n"
                                    "if not should_run('gated'): raise SystemExit(0)\n")
    (hooks / "ungated.py").write_text("# mentions should_run but never calls it\nprint(1)\n")
    (hooks / "helper.py").write_text("print(2)\n")
    (tmp_path / ".claude" / "settings.json").write_text(
        '{"hooks": {"Stop": [{"hooks": ['
        '{"type": "command", "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/gated.py"},'
        '{"type": "command", "command": "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/ungated.py"}'
        ']}]}}')
    return tmp_path


def test_blocks_edit_of_existing_ruff_toml(tmp_path):
    t = tmp_path / "ruff.toml"
    t.write_text("[lint]\n")
    r = gate(edit(t))
    assert r.returncode == 2 and "GATE CONFIG" in r.stderr


def test_blocks_pytest_ini_in_any_directory(tmp_path):
    for rel in ("pytest.ini", "config/pytest.ini"):
        t = tmp_path / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text("[pytest]\n")
        assert gate(edit(t)).returncode == 2, rel


def test_allows_first_time_creation(tmp_path):
    assert gate(edit(tmp_path / "ruff.toml")).returncode == 0


def test_pyproject_toml_is_deliberately_not_protected(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_text("[project]\n")
    assert gate(edit(t)).returncode == 0


def test_unprotected_file_untouched(tmp_path):
    t = tmp_path / "module.py"
    t.write_text("x = 1\n")
    r = gate(edit(t))
    assert r.returncode == 0 and not r.stdout.strip() and not r.stderr.strip()


def test_case_variant_is_protected(tmp_path):
    t = tmp_path / "RUFF.TOML"
    t.write_text("[lint]\n")
    assert gate(edit(t)).returncode == 2


def test_dangling_symlink_counts_as_existing(tmp_path):
    t = tmp_path / ".eslintrc.js"
    os.symlink(tmp_path / "missing-target", t)
    assert gate(edit(t)).returncode == 2


def test_operator_override_allows_with_a_note(tmp_path):
    t = tmp_path / "ruff.toml"
    t.write_text("[lint]\n")
    r = gate(edit(t), env={"HOOK_KIT_GATE_CONFIG_OVERRIDE": "1"})
    assert r.returncode == 0 and "override" in r.stdout.lower()


def test_non_edit_tools_pass(tmp_path):
    t = tmp_path / "ruff.toml"
    t.write_text("[lint]\n")
    assert gate({"tool_name": "Read", "tool_input": {"file_path": str(t)}}).returncode == 0


@pytest.mark.parametrize("raw", ["null", "42", "[]", "not json at all", ""])
def test_small_malformed_payload_exits_zero(raw):
    assert run_kit(["check-gate-config"], raw=raw).returncode == 0


def test_oversized_unparseable_payload_fails_closed():
    r = run_kit(["check-gate-config"], raw="{" + "x" * (1024 * 1024 + 10))
    assert r.returncode == 2 and "1 MiB" in r.stderr


def test_config_can_add_and_disable_protected_names():
    m = G.protected_map({"gate_config": {"extra_protected": {"Lint.CFG": "ours"},
                                         "disable": ["pytest.ini"]}})
    assert m["lint.cfg"] == "ours" and "pytest.ini" not in m


def test_ecc_list_is_carried():
    for name in (".eslintrc.json", "biome.json", ".prettierrc", ".shellcheckrc", ".ruff.toml"):
        assert name in G.DEFAULT_PROTECTED


# --- profiles ---------------------------------------------------------------

def test_kit_guards_run_in_every_profile(env):
    for prof in ("minimal", "standard", "strict"):
        env(prof)
        assert all(P.should_run(g) for g in P.KIT_GUARDS)


def test_standard_tier_is_gated_by_profile(env):
    env("minimal")
    assert P.should_run("lint", CFG) is False
    env("standard")
    assert P.should_run("lint", CFG) is True


def test_strict_tier_only_in_strict(env):
    env("standard")
    assert P.should_run("deep_scan", CFG) is False
    env("strict")
    assert P.should_run("deep_scan", CFG) is True


def test_unknown_hook_defaults_to_standard_and_bad_profile_to_standard(env):
    env("minimal")
    assert P.should_run("whatever") is False
    env("bogus")
    assert P.get_profile() == "standard" and P.should_run("whatever") is True


def test_operator_disable_beats_always_on(env):
    env("strict", "check-command")
    assert P.should_run("check-command") is False


def test_disabled_guard_really_is_skipped_by_the_hook(tmp_path):
    r = run_kit(["check-command"], payload={"tool_name": "Bash",
                                            "tool_input": {"command": "git clean -fd"}},
                env={"DISABLED_HOOKS": "check-command"})
    assert r.returncode == 0


def test_profile_info_reports_always_on_and_gated_split(env):
    env("minimal")
    info = P.profile_info(None, CFG)
    assert f"{len(P.KIT_GUARDS | {'must'})} always-on" in info and "0 gated-active" in info


def test_registered_ungated_disable_is_named_as_not_disabled(tmp_path):
    root = _project(tmp_path)
    assert P.unenforceable_disables(root, {"ungated", "gated", "helper", "nope"}) == ["ungated"]


def test_consults_gate_matches_a_call_not_a_mention(tmp_path):
    root = _project(tmp_path)
    hooks = root / ".claude" / "hooks"
    assert P.consults_gate(hooks, "gated") is True
    assert P.consults_gate(hooks, "ungated") is False
    assert P.consults_gate(hooks, "missing") is None


def test_profile_info_says_not_actually_disabled(tmp_path, env):
    root = _project(tmp_path)
    env("standard", "ungated")
    assert "NOT ACTUALLY DISABLED (1): ungated" in P.profile_info(root)


def test_gate_config_through_a_symlink_is_judged_as_its_target(tmp_path):
    (tmp_path / "ruff.toml").write_text("x = 1\n")
    (tmp_path / "innocent.txt").symlink_to(tmp_path / "ruff.toml")
    p = {"tool_name": "Edit", "cwd": str(tmp_path),
         "tool_input": {"file_path": str(tmp_path / "innocent.txt"), "old_string": "x", "new_string": "y"}}
    assert run_kit(["check-gate-config"], payload=p).returncode == 2


def test_gate_config_case_and_new_file_behaviour_is_kept(tmp_path):
    (tmp_path / "RUFF.TOML").write_text("x = 1\n")
    p = {"tool_name": "Write", "cwd": str(tmp_path),
         "tool_input": {"file_path": str(tmp_path / "RUFF.TOML"), "content": "y"}}
    assert run_kit(["check-gate-config"], payload=p).returncode == 2
    fresh = {"tool_name": "Write", "cwd": str(tmp_path),
             "tool_input": {"file_path": str(tmp_path / "newdir" / "ruff.toml"), "content": "y"}}
    assert run_kit(["check-gate-config"], payload=fresh).returncode == 0
    plain = {"tool_name": "Write", "cwd": str(tmp_path),
             "tool_input": {"file_path": str(tmp_path / "notes.txt"), "content": "y"}}
    assert run_kit(["check-gate-config"], payload=plain).returncode == 0
