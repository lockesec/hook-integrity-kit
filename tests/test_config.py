"""Kit configuration: a bad config entry is named on stderr by every command that loads it,
the command guard judges Bash unless a shell tool is configured, and ``install`` can widen
the matcher."""
from __future__ import annotations

import json

import pytest

from conftest import hooks_block, project_from_files, run_kit


def _tool_payload(tool, command):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": "/work/proj",
            "tool_input": {"command": command}}


BAD_CONFIGS = [
    ({"commands": {"extra_rules": [{"id": "r", "pattern": "("}]}}, "extra_rules[0]"),
    ({"commands": {"extra_rules": "not a list"}}, "extra_rules"),
    ({"commands": {"disable": "kill-all-processes"}}, "disable"),
    ({"commands": {"disable": ["no-such-rule"]}}, "no-such-rule"),
    ({"commands": None}, "commands"),
    ({"writes": {"disable": ["no-such-write-rule"]}}, "no-such-write-rule"),
    ({"writes": {"extra_block": [{"pattern": "["}]}}, "extra_block[0]"),
    ({"gate_config": {"disable": ["no-such.cfg"]}}, "no-such.cfg"),
    ({"integrity": []}, "integrity"),
]


@pytest.mark.parametrize("cfg,needle", BAD_CONFIGS)
def test_every_command_that_loads_the_config_warns_about_a_bad_entry(tmp_path, cfg, needle):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n",
                               ".claude/hook-integrity-kit.json": json.dumps(cfg)},
                    hooks_block(".claude/hooks/a.py"))
    runs = [run_kit(["rules", "--root", str(root)]),
            run_kit(["bless", "--root", str(root)]),
            run_kit(["profile", "--root", str(root)]),
            run_kit(["check-gate-config"], payload={"tool_name": "Write", "cwd": str(root),
                                                    "tool_input": {"file_path": str(root / "x.txt"),
                                                                   "content": "x"}}),
            run_kit(["check-command"], payload={"tool_name": "Bash", "cwd": str(root),
                                                "tool_input": {"command": "ls"}}),
            run_kit(["check-write"], payload={"tool_name": "Write", "cwd": str(root),
                                              "tool_input": {"file_path": str(root / "x.txt"),
                                                             "content": "x"}})]
    for r in runs:
        assert needle in r.stderr, (r.args, r.stderr)
    # and the defaults still hold: a bad config never weakens them
    assert runs[5].returncode == 0


def test_a_good_config_is_silent(tmp_path):
    cfg = {"commands": {"extra_rules": [{"id": "r", "pattern": "terraform destroy"}],
                        "disable": ["kill-all-processes"]},
           "writes": {"disable": ["env-file"]}, "gate_config": {"disable": ["pytest.ini"]}}
    root = project_from_files(tmp_path, {".claude/hook-integrity-kit.json": json.dumps(cfg)})
    r = run_kit(["rules", "--root", str(root)])
    assert r.returncode == 0 and r.stderr == ""


def test_check_command_judges_only_bash_by_default():
    r = run_kit(["check-command"], payload=_tool_payload("PowerShell", "git clean -fd"))
    assert r.returncode == 0
    r = run_kit(["check-command"], payload=_tool_payload("Bash", "git clean -fd"))
    assert r.returncode == 2


def test_a_configured_shell_tool_is_judged_like_bash(tmp_path):
    cfgp = tmp_path / "cfg.json"
    cfgp.write_text(json.dumps({"commands": {"shell_tools": ["Bash", "PowerShell"]}}))
    r = run_kit(["check-command", "--config", str(cfgp)],
                payload=_tool_payload("PowerShell", "git clean -fd"))
    assert r.returncode == 2 and "git-clean-force-directories" in r.stderr
    ok = run_kit(["check-command", "--config", str(cfgp)],
                 payload=_tool_payload("PowerShell", "git status"))
    assert ok.returncode == 0
    other = run_kit(["check-command", "--config", str(cfgp)],
                    payload=_tool_payload("Monitor", "git clean -fd"))
    assert other.returncode == 0                          # not in the list


def test_install_can_widen_the_matcher():
    r = run_kit(["install", "--shell-tool", "PowerShell"])
    hooks = json.loads(r.stdout)["hooks"]["PreToolUse"]
    assert hooks[0]["matcher"] == "Bash|PowerShell"
    assert json.loads(run_kit(["install"]).stdout)["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_a_malformed_shell_tools_entry_warns_and_keeps_bash(tmp_path):
    cfgp = tmp_path / "cfg.json"
    cfgp.write_text(json.dumps({"commands": {"shell_tools": "PowerShell"}}))
    r = run_kit(["check-command", "--config", str(cfgp)], payload=_tool_payload("Bash", "git clean -fd"))
    assert r.returncode == 2 and "shell_tools" in r.stderr
