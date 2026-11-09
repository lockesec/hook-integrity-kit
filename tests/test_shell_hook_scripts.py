"""Shell hooks: every literal project file a hook script names is hashed, whatever wrapper,
option cluster, cd, subshell, function, heredoc or quoting surrounds it. What cannot be placed
is named NOT CHECKED, and the work is linear under a budget. Also covers extensionless
scripts and settings commands that name project files."""
from __future__ import annotations

import json
import time

import pytest

from conftest import (
    bless, cmd_block, entry, hooks_block, not_checked, project, project_from_files, run_kit,
    settings_with, write_settings,
)
from hook_integrity_kit import manifest as M


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


def _verify_json(root):
    r = _verify(root, "--json")
    return r.returncode, json.loads(r.stdout)


def _shell_project(tmp_path, body, extra=None):
    files = {".claude/hooks/run.sh": body, ".claude/hooks/helper.sh": "echo helper\n",
             ".claude/hooks/p.py": "import sibling\nprint(1)\n",
             ".claude/hooks/sibling.py": "x = 1\n"}
    files.update(extra or {})
    settings = {"SessionStart": [{"matcher": "", "hooks": [
        {"type": "command", "command": "sh ${CLAUDE_PROJECT_DIR}/.claude/hooks/run.sh"}]}]}
    return project_from_files(tmp_path, files, settings)


def _cmd_settings(command, args=None):
    entry = {"type": "command", "command": command}
    if args is not None:
        entry["args"] = args
    return {"SessionStart": [{"matcher": "", "hooks": [entry]}]}


def _follow(tmp_path, body, files=None, hook="hook.sh"):
    base = {"helper.sh": "echo helper\n", "h.sh": "echo root-h\n", "x.sh": "echo root-x\n",
            "sub/h.sh": "echo sub-h\n", "sub/x.sh": "echo sub-x\n", "pre.js": "1\n",
            "n.js": "1\n", hook: "#!/bin/sh\n" + body + "\n"}
    base.update(files or {})
    root = project_from_files(tmp_path, base)
    called, shells, pys, notes = M.follow_shell_calls(root, [hook])
    return set(called), notes


def _named(notes, needle=None):
    return [n for n in notes if needle is None or needle in n]


def _shell_helper_project(tmp_path, body, extra=None):
    files = {".claude/hooks/run.sh": body, ".claude/hooks/helper.sh": "echo helper\n"}
    files.update(extra or {})
    settings = {"SessionStart": [{"matcher": "", "hooks": [
        {"type": "command", "command": "sh ${CLAUDE_PROJECT_DIR}/.claude/hooks/run.sh"}]}]}
    return project_from_files(tmp_path, files, settings)


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


BASE = {"h.sh": "echo h\n", "h.py": "x = 1\n", "sub/h.sh": "echo sub\n", "pre.js": "1\n",
        "pre.rb": "1\n", "pre.php": "1\n", "pre.sh": "1\n", "lib/m.py": "1\n",
        "sub/inner/h.sh": "echo inner\n", "h.rb": "1\n", "h.js": "1\n", "h.php": "1\n"}


def _bless_tamper_verify(tmp_path, body, target, files=None, name="proj"):
    """bless a project whose a.sh holds ``body``, tamper ``target``, verify. Returns
    (verify result, bless result)."""
    f = dict(BASE)
    f.update(files or {})
    f["a.sh"] = "#!/bin/sh\n" + body + "\n"
    root = _script_project(tmp_path, f, name)
    b = run_kit(["bless", "--root", str(root)])
    assert b.returncode == 0, b.stderr + b.stdout
    with open(root / target, "a", encoding="utf-8") as fh:
        fh.write("\n# tampered\n")
    return run_kit(["verify", "--root", str(root)]), b


def _caught(v, b):
    return v.returncode == 1


@pytest.mark.parametrize("cmd", ["bash .claude/hooks/run", "sh ./.claude/hooks/run",
                                 ".claude/hooks/run --flag"])
def test_extensionless_relative_script_is_hashed_and_its_swap_is_drift(tmp_path, cmd):
    root = tmp_path / "r"
    (root / ".claude/hooks").mkdir(parents=True)
    (root / ".claude/hooks/run").write_text("#!/bin/sh\necho ok\n")
    settings_with(root, entry(cmd))
    base = bless(root)
    assert ".claude/hooks/run" in {f["path"] for f in base["files"]}
    (root / ".claude/hooks/run").write_text("#!/bin/sh\necho swapped\n")
    res = M.check(root)
    assert res["status"] == "drift" and ".claude/hooks/run" in res["modified"]


def test_words_that_are_not_project_files_are_not_scripts(tmp_path):
    root = tmp_path / "r"
    settings_with(root, entry("bash -c true"))
    assert bless(root)["files"] == []


def test_a_quoted_path_with_a_space_survives_an_apostrophe_in_a_comment(tmp_path):
    files = {"my hooks/x.sh": "echo x\n"}
    v, b = _bless_tamper_verify(tmp_path, "echo hi # don't panic\nbash 'my hooks/x.sh'", "my hooks/x.sh",
                                files)
    assert v.returncode == 1, v.stdout


def test_an_unsplittable_script_is_named(tmp_path):
    f = dict(BASE)
    f["a.sh"] = "#!/bin/sh\necho \"unbalanced\nbash h.sh\n"
    root = _script_project(tmp_path, f)
    b = run_kit(["bless", "--root", str(root)])
    assert "could not be split into shell words" in b.stdout + b.stderr


def test_project_dir_with_a_default_is_the_project_dir(tmp_path):
    f = dict(BASE)
    f["a.sh"] = "#!/bin/sh\necho a\n"
    root = _script_project(tmp_path, f)
    write_settings(root, {"SessionStart": [{"matcher": "", "hooks": [
        {"type": "command", "command": "bash ${CLAUDE_PROJECT_DIR:-.}/a.sh"}]}]})
    b = run_kit(["bless", "--root", str(root)])
    assert b.returncode == 0, b.stdout + b.stderr
    assert "runs :-.}" not in b.stdout and "no file inside the project" not in b.stdout, b.stdout
    with open(root / "a.sh", "a") as fh:
        fh.write("# tampered\n")
    assert run_kit(["verify", "--root", str(root)]).returncode == 1


def test_a_regex_dollar_anchor_is_not_ansi_c_quoting(tmp_path):
    f = dict(BASE)
    f["a.sh"] = "#!/bin/sh\njq -r .x | grep -qE '\\.(ts|js)$' && echo y\ngrep -q \"^foo$\" f\n"
    root = _script_project(tmp_path, f)
    b = run_kit(["bless", "--root", str(root)])
    assert "$'...' quoting" not in b.stdout + b.stderr


@pytest.mark.parametrize("line,needle", [("run-parts hooks.d", "runs a directory"),
                                         ("python3 tools", "runs a directory"),
                                         ("bash missing.sh", "not a file where the script is run")])
def test_an_operand_that_is_a_directory_or_missing_is_named(tmp_path, line, needle):
    f = dict(BASE)
    f.update({"hooks.d/x.sh": "echo\n", "tools/__main__.py": "1\n"})
    f["a.sh"] = "#!/bin/sh\n" + line + "\n"
    root = _script_project(tmp_path, f)
    b = run_kit(["bless", "--root", str(root)])
    assert needle in b.stdout + b.stderr, b.stdout


@pytest.mark.parametrize("line", ["npx prettier --write \"$@\"", "python3 h.py --strict", "bash -c 'cd sub && echo'",
                                  "node h.js \"$@\"", "python3 -W ignore h.py", "bash -o pipefail h.sh",
                                  "jq -r .x | python3 -c 'print(1)'"])
def test_realistic_hooks_get_no_spurious_note(tmp_path, line):
    f = dict(BASE)
    f["a.sh"] = "#!/bin/sh\n" + line + "\n"
    root = _script_project(tmp_path, f)
    out = run_kit(["bless", "--root", str(root)]).stdout
    assert "not a file where the script is run" not in out and "runs a directory" not in out, out


@pytest.mark.parametrize("var", ["PYTHONUSERBASE", "NODE_PATH", "LD_LIBRARY_PATH", "PYTHONHOME",
                                 "PERL5LIB", "RUBYLIB", "GEM_PATH", "LD_PRELOAD"])
def test_more_loading_variables_are_named(tmp_path, var):
    f = dict(BASE)
    f["a.sh"] = f"#!/bin/sh\n{var}=x python3 h.py\n"
    root = _script_project(tmp_path, f)
    assert var in run_kit(["bless", "--root", str(root)]).stdout


@pytest.mark.parametrize("line,target", [
    ("bash .claude/hooks/helper.sh", ".claude/hooks/helper.sh"),
    ("sh .claude/hooks/helper.sh", ".claude/hooks/helper.sh"),
    ("./.claude/hooks/helper.sh", ".claude/hooks/helper.sh"),
    ('bash "$CLAUDE_PROJECT_DIR/.claude/hooks/helper.sh"', ".claude/hooks/helper.sh"),
    ("bash ${CLAUDE_PROJECT_DIR}/.claude/hooks/helper.sh --flag", ".claude/hooks/helper.sh"),
    ("python3 .claude/hooks/p.py", ".claude/hooks/p.py"),
    ("python3 -u .claude/hooks/p.py", ".claude/hooks/p.py"),
    ("echo go && bash .claude/hooks/helper.sh", ".claude/hooks/helper.sh"),
])
def test_a_helper_run_by_a_shell_hook_is_hashed_and_its_tampering_is_drift(tmp_path, line, target):
    root = _shell_project(tmp_path, line + "\n")
    assert _bless(root).returncode == 0
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert target in {f["path"] for f in base["files"]}
    assert _verify(root).returncode == 0
    (root / target).write_text((root / target).read_text() + "\n# tampered\n")
    rc, out = _verify_json(root)
    assert rc == 1 and target in out["modified"]


def test_the_python_helper_of_a_shell_hook_has_its_imports_walked(tmp_path):
    root = _shell_project(tmp_path, "python3 .claude/hooks/p.py\n")
    assert _bless(root).returncode == 0
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert ".claude/hooks/sibling.py" in {f["path"] for f in base["files"]}


def test_a_helper_of_a_helper_is_followed(tmp_path):
    root = _shell_project(tmp_path, "bash .claude/hooks/helper.sh\n",
                          {".claude/hooks/helper.sh": "bash .claude/hooks/deep.sh\n",
                           ".claude/hooks/deep.sh": "echo deep\n"})
    assert _bless(root).returncode == 0
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert ".claude/hooks/deep.sh" in {f["path"] for f in base["files"]}


@pytest.mark.parametrize("line", [
    'bash "$HELPER"',
    'bash "$(dirname "$0")/helper.sh"',
    "bash $CLAUDE_PROJECT_DIR/.claude/hooks/$NAME.sh",
    "bash .claude/hooks/missing-helper.sh",
])
def test_a_helper_the_kit_cannot_follow_is_named_not_checked(tmp_path, line):
    root = _shell_project(tmp_path, line + "\n")
    r = _bless(root)
    assert r.returncode == 0 and "NOT CHECKED" in r.stdout and "run.sh" in r.stdout
    v = _verify(root)
    assert "NOT CHECKED" in v.stdout and "run.sh" in v.stdout


def test_a_shell_hook_that_runs_nothing_else_gets_no_helper_note(tmp_path):
    root = _shell_project(tmp_path, 'echo hello\nls -l\nrm_tmp() { echo x; }\n')
    r = _bless(root)
    assert r.returncode == 0
    assert "runs another" not in r.stdout and "cannot follow" not in r.stdout


SPACE_FORMS = [
    ('python3 "$CLAUDE_PROJECT_DIR/.claude/my hooks/a.py"', None),
    ('python3 "${CLAUDE_PROJECT_DIR}/.claude/my hooks/a.py"', None),
    ("python3 '.claude/my hooks/a.py'", None),
    ('python3 ".claude/my hooks/a.py"', None),
    ("python3 .claude/my\\ hooks/a.py", None),
    ('"$CLAUDE_PROJECT_DIR"/.claude/my\\ hooks/a.py', None),
    ("python3", ["${CLAUDE_PROJECT_DIR}/.claude/my hooks/a.py"]),
    ("python3", [".claude/my hooks/a.py"]),
]


@pytest.mark.parametrize("command,args", SPACE_FORMS)
def test_a_hook_path_with_a_space_is_hashed_whole(tmp_path, command, args):
    root = project_from_files(tmp_path, {".claude/my hooks/a.py": "print(1)\n"},
                    _cmd_settings(command, args))
    r = _bless(root)
    assert r.returncode == 0 and "MISSING" not in r.stdout, r.stdout
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert [f["path"] for f in base["files"]] == [".claude/my hooks/a.py"]
    assert base["files"][0]["sha256"]
    assert _verify(root).returncode == 0
    (root / ".claude/my hooks/a.py").write_text("print(2)\n")
    assert _verify(root).returncode == 1


@pytest.mark.parametrize("command", [
    "cd .claude/hooks && python3 a.py",
    "cd .claude/hooks; python3 a.py",
    "cd $CLAUDE_PROJECT_DIR/.claude/hooks && python3 a.py",
    'cd "$CLAUDE_PROJECT_DIR/.claude/hooks" && bash b.sh',
])
def test_a_leading_cd_moves_the_relative_script(tmp_path, command):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": "print(1)\n", ".claude/hooks/b.sh": "echo\n"},
                    _cmd_settings(command))
    r = _bless(root)
    assert r.returncode == 0 and "MISSING" not in r.stdout, r.stdout
    assert _verify(root).returncode == 0
    target = "b.sh" if "b.sh" in command else "a.py"
    (root / ".claude/hooks" / target).write_text("print(2)\n")
    assert _verify(root).returncode == 1


@pytest.mark.parametrize("line", [
    "bash -e helper.sh", "sh -e helper.sh", "bash -e -x helper.sh",
    "bash -o errexit -e helper.sh", "bash -euo pipefail helper.sh",
    "bash -o pipefail helper.sh", "dash -eu helper.sh", "zsh -e helper.sh",
    "ksh -x helper.sh", "bash +e helper.sh", "bash --norc -e helper.sh",
    "bash -O extglob helper.sh", "bash -- helper.sh", "ash helper.sh",
    "bash -p helper.sh", "sh -r helper.sh",
])
def test_shell_option_clusters_do_not_hide_the_script(tmp_path, line):
    called, notes = _follow(tmp_path, line)
    assert "helper.sh" in called, (line, notes)
    assert not _named(notes, "not a file"), notes


def test_perl_and_node_script_operands_are_followed_with_their_options(tmp_path):
    called, _ = _follow(tmp_path, "node --no-warnings n.js")
    assert "n.js" in called


def test_registration_command_with_shell_option_cluster_is_hashed(tmp_path):
    root = project_from_files(tmp_path, {".claude/hooks/a.sh": "echo a\n"})
    regs = M.Registrations(root)
    regs.add_block(hooks_block(".claude/hooks/a.sh"), "settings.json")
    regs.add_block({"Stop": [{"hooks": [{"type": "command",
                    "command": "bash -euo pipefail .claude/hooks/a.sh"}]}]}, "settings.json")
    assert ".claude/hooks/a.sh" in regs.shell
    assert "pipefail" not in regs.shell and "pipefail" not in regs.scripts


@pytest.mark.parametrize("cmd", [
    "cd -P sub && sh x.sh", "pushd -n sub && sh x.sh", "cd /tmp && sh x.sh", "cd .. && sh x.sh",
    'cd "$D" && sh x.sh', "cd && sh x.sh", "cd - && sh x.sh",
])
def test_registration_cd_the_kit_cannot_place_never_hashes_the_root_script(tmp_path, cmd):
    root = project_from_files(tmp_path, {"x.sh": "echo root\n"})
    block = {"Stop": [{"hooks": [{"type": "command", "command": cmd}]}]}
    regs = M.Registrations(root)
    regs.add_block(block, "settings.json")
    assert "x.sh" not in regs.scripts and "x.sh" not in regs.shell
    notes = M.not_checked_handlers(block, "settings.json", root)
    assert any("cd" in n for n in notes), notes


@pytest.mark.parametrize("cmd", ["cd sub && sh x.sh", "cd -P sub && sh x.sh".replace("-P ", ""),
                                 "pushd sub && sh x.sh", "(cd sub && sh x.sh)"])
def test_registration_cd_to_a_literal_sub_directory_hashes_that_script(tmp_path, cmd):
    root = project_from_files(tmp_path, {"x.sh": "echo root\n", "sub/x.sh": "echo sub\n"})
    regs = M.Registrations(root)
    regs.add_block({"Stop": [{"hooks": [{"type": "command", "command": cmd}]}]}, "settings.json")
    assert "sub/x.sh" in regs.scripts and "x.sh" not in regs.scripts


@pytest.mark.parametrize("line", [
    "timeout 5 ./h.sh", "timeout -s KILL 5 ./h.sh", "timeout --signal=KILL -k 2 5 ./h.sh",
    "nice ./h.sh", "nice -n 5 ./h.sh", "nice -5 ./h.sh", "nohup ./h.sh", "setsid ./h.sh",
    "setsid -w ./h.sh", "stdbuf -o0 ./h.sh", "stdbuf -oL -eL ./h.sh", "stdbuf -o 0 ./h.sh",
    "flock l ./h.sh", "flock -n l ./h.sh", "flock -w 3 l ./h.sh", "command ./h.sh",
    "command -p ./h.sh", "env -i ./h.sh", "env -u X A=b ./h.sh", "env A=b bash h.sh",
    "sudo ./h.sh", "sudo -u x ./h.sh", "sudo -n -E ./h.sh", "sudo -u x -g y bash h.sh",
    "doas -u x ./h.sh", "exec ./h.sh", "exec -a name ./h.sh", "time ./h.sh", "time -p ./h.sh",
    "xargs ./h.sh", "xargs -n 1 ./h.sh", "xargs -I {} ./h.sh {}", "busybox sh h.sh",
    "busybox ash h.sh", "ash h.sh", "bash < h.sh", "bash -s < h.sh", "sh - < h.sh",
    "nice timeout 3 sudo -u a env -i ./h.sh", "ionice -c 3 ./h.sh", "builtin command ./h.sh",
    "/usr/bin/timeout 5 ./h.sh", "/usr/bin/env bash h.sh", "A=1 timeout 5 ./h.sh",
])
def test_common_wrappers_are_followed_to_the_script(tmp_path, line):
    called, notes = _follow(tmp_path, line)
    assert "h.sh" in called, (line, called, notes)


def test_busybox_inline_and_plain_commands_stay_quiet(tmp_path):
    called, notes = _follow(tmp_path, "echo hi\nls -l\ngrep x y\n")
    assert called == set() and notes == []


@pytest.mark.parametrize("line", ["bash -e .claude/hooks/helper.sh",
                                  "bash -euo pipefail .claude/hooks/helper.sh",
                                  "timeout 5 .claude/hooks/helper.sh",
                                  "(cd .claude/hooks && ./helper.sh)"])
def test_end_to_end_a_helper_behind_options_wrappers_or_cd_is_hashed_and_drift_is_seen(
        tmp_path, line):
    root = _shell_helper_project(tmp_path, line + "\n")
    assert _bless(root).returncode == 0
    base = json.loads((root / ".claude" / "hook-integrity.json").read_text())
    assert ".claude/hooks/helper.sh" in {f["path"] for f in base["files"]}
    assert _verify(root).returncode == 0
    (root / ".claude" / "hooks" / "helper.sh").write_text("echo tampered\n")
    v = _verify(root)
    assert v.returncode != 0 and "helper.sh" in v.stdout


WRAPPER_SHAPES = [
    "sudo -Eu root bash h.sh", "sudo -nu root bash h.sh", "sudo -ug root bash h.sh",
    "doas -nu x bash h.sh", "timeout -vk 1 5 bash h.sh", "timeout -vs KILL 5 bash h.sh",
    "flock -nw 5 lock bash h.sh", "flock -wn 5 lock bash h.sh", "xargs -0n 1 bash h.sh",
    "env -iu X bash h.sh", "time -po out bash h.sh", "2>&1 bash h.sh", "echo `bash h.sh`",
    "cat <(bash h.sh)", "builtin source h.sh", "busybox env bash h.sh",
    "busybox timeout 5 sh h.sh", "flock lock -c 'bash h.sh'", "at now <<< 'bash h.sh'",
    "cat h.sh | bash", "ksh93 h.sh", "bash5 h.sh", "bash-5.1 h.sh", "rbash h.sh",
    "gosu root bash h.sh", "su-exec root bash h.sh", "tini -- bash h.sh",
    "dumb-init bash h.sh", "chronic bash h.sh", "ts bash h.sh", "entr bash h.sh",
    "expect -c 'spawn bash h.sh'", "nohup setsid nice -n 5 ionice -c3 bash h.sh",
    'bash "h".sh', "bash h\\.sh", "bash ./h.sh", "bash sub/../h.sh",
    "bash -c 'bash h.sh'", "bash -oe pipefail h.sh", "eval 'bash h.sh'",
    "x=$(bash h.sh)", "(bash h.sh)", "{ bash h.sh; }", "if true; then bash h.sh; fi",
]


@pytest.mark.parametrize("line", WRAPPER_SHAPES)
def test_wrapper_and_syntax_shapes_still_hash_the_script(tmp_path, line):
    v, b = _bless_tamper_verify(tmp_path, line, "h.sh")
    assert _caught(v, b), (line, v.stdout, b.stdout)


@pytest.mark.parametrize("line", [
    "pypy3 h.py", "python3.12t h.py", "pythonw h.py", "pipenv run python h.py",
    "pdm run h.py", "uv run h.py", "python3 -u h.py", "env PYTHONPATH=lib python3 h.py",
])
def test_python_shapes_hash_the_script(tmp_path, line):
    v, b = _bless_tamper_verify(tmp_path, line, "h.py")
    assert _caught(v, b), (line, v.stdout, b.stdout)


@pytest.mark.parametrize("line,target", [
    ("ruby --require ./pre.rb h.rb", "pre.rb"), ("ruby --require=./pre.rb h.rb", "pre.rb"),
    ("ruby -C sub h.rb", "h.rb"), ("php -d auto_prepend_file=pre.php h.php", "pre.php"),
    ("php -z ext h.php", "h.php"), ("NODE_OPTIONS=--require=./pre.js node h.js", "pre.js"),
    ("env NODE_OPTIONS='-r ./pre.js' node h.js", "pre.js"), ("BASH_ENV=pre.sh bash h.sh", "pre.sh"),
    ("PYTHONPATH=lib python3 h.py", "h.py"), ("node --stack-size 100 h.js", "h.js"),
    ("node --inspect-port 9229 h.js", "h.js"), ("node --watch-path ./src h.js", "h.js"),
    ("node --test-reporter spec h.js", "h.js"),
])
def test_interpreter_preloads_and_value_options(tmp_path, line, target):
    v, b = _bless_tamper_verify(tmp_path, line, target)
    assert _caught(v, b), (line, v.stdout, b.stdout)


def test_preload_variables_are_named(tmp_path):
    for var in ("NODE_OPTIONS", "BASH_ENV", "ENV", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT",
                "PYTHONPATH"):
        _, b = _bless_tamper_verify(tmp_path, f"{var}=x bash h.sh", "h.sh", name="p" + var)
        assert "NOT CHECKED" in b.stdout and var in b.stdout, (var, b.stdout)


CD_SHAPES = [
    "(cd sub; echo ')'; bash h.sh)", "cd sub | cat; bash h.sh", "cd sub &\nbash h.sh",
    '[ -n "$X" ] && cd sub\nbash h.sh', "test -d nope || cd sub\nbash h.sh",
    "eval 'cd sub'\nbash h.sh", "go() { cd sub; }\ngo\nbash h.sh",
    "cat <<EOF\ncd sub\nEOF\nbash h.sh", "cd sub\nbash h.sh", "pushd sub\nbash h.sh\npopd",
    "bash -c 'cd sub && bash h.sh'", "env -C sub bash h.sh", "make -C sub; bash h.sh",
    "git -C sub run; bash h.sh", "sudo --chdir=sub bash h.sh",
]


@pytest.mark.parametrize("line", CD_SHAPES)
@pytest.mark.parametrize("target", ["h.sh", "sub/h.sh"])
def test_cd_shapes_hash_both_candidates(tmp_path, line, target):
    v, b = _bless_tamper_verify(tmp_path, line, target)
    assert _caught(v, b), (line, target, v.stdout, b.stdout)


def test_cdpath_makes_a_candidate(tmp_path):
    v, b = _bless_tamper_verify(tmp_path, "CDPATH=sub; cd inner; bash h.sh", "sub/inner/h.sh")
    assert v.returncode == 1, (v.stdout, b.stdout)


def test_sourced_file_that_cds(tmp_path):
    files = {"cdr.sh": "cd sub\n"}
    v, b = _bless_tamper_verify(tmp_path, "source cdr.sh\nbash h.sh", "sub/h.sh", files)
    assert v.returncode == 1, (v.stdout, b.stdout)


def test_chained_cd_directories_are_candidates(tmp_path):
    v, b = _bless_tamper_verify(tmp_path, "cd sub; cd inner; bash h.sh", "sub/inner/h.sh")
    assert v.returncode == 1


def test_a_hashed_file_is_hashed_through_a_project_dir_prefix(tmp_path):
    v, b = _bless_tamper_verify(tmp_path, 'bash "${CLAUDE_PROJECT_DIR}/sub/h.sh"', "sub/h.sh")
    assert v.returncode == 1
    v, b = _bless_tamper_verify(tmp_path, "bash $CLAUDE_PROJECT_DIR/h.sh", "h.sh", name="q")
    assert v.returncode == 1


@pytest.mark.parametrize("body,needle", [
    ('cd "$D"', "cd"), ("cd /tmp", "cd"), ("eval \"$X\"", "eval"), ('source "$F"', "source"),
    ("f() { :; }", "function"), ("alias ll=ls", "alias"), ("exec >out.log", "exec"),
    ("shopt -s globstar", "globbing"), ("bash h*.sh", "glob"), ('bash "$(dirname $0)/x.sh"',
                                                                  "computed"),
    ("bash $DIR/x.sh", "variable"), ("CDPATH=$X; cd sub", "CDPATH"), ("cd", "cd"),
    ("python3 -m mod", "python -m"), ("python3 -c 'pass'", "python -m"),
])
def test_unmodelled_constructs_are_named_once_per_script(tmp_path, body, needle):
    _, b = _bless_tamper_verify(tmp_path, body, "h.sh")
    lines = [ln for ln in b.stdout.splitlines() if ln.strip().startswith("a.sh: uses")
             or "a.sh: uses" in ln]
    assert len(lines) == 1 and needle in lines[0], (body, b.stdout)
    assert "not hashed" in lines[0]


def test_a_plain_script_is_quiet(tmp_path):
    _, b = _bless_tamper_verify(tmp_path, "echo hi\nls -l\ngrep x y\n[ -n \"$X\" ] && echo y",
                                "h.sh")
    assert "a.sh: uses" not in b.stdout


def test_depth_16_three_way_cd_chain_is_linear(tmp_path):
    files = {}
    for i in range(17):
        nxt = (f"(cd a; bash $CLAUDE_PROJECT_DIR/s{i + 1}.sh)\n(cd b; bash $CLAUDE_PROJECT_DIR/"
               f"s{i + 1}.sh)\n(cd c; bash $CLAUDE_PROJECT_DIR/s{i + 1}.sh)\n") if i < 16 else "echo end\n"
        files[f"s{i}.sh"] = nxt
    for d in "abc":
        files[f"{d}/keep"] = "x\n"
    files["a.sh"] = "bash s0.sh\n"
    root = _script_project(tmp_path, files)
    t = time.time()
    called, shells, _, notes = M.follow_shell_calls(root, ["a.sh"])
    assert time.time() - t < 2, "not linear"
    assert {f"s{i}.sh" for i in range(17)} <= set(called)
    t = time.time()
    r = run_kit(["bless", "--root", str(root)])
    assert r.returncode == 0 and time.time() - t < 2 + 1.5, r.stdout


def test_work_budget_is_not_evaluable_not_a_hang(tmp_path, monkeypatch):
    files = {f"s{i}.sh": f"bash s{i + 1}.sh\n" for i in range(30)}
    files["a.sh"] = "bash s0.sh\n"
    root = _script_project(tmp_path, files)
    monkeypatch.setattr(M, "FOLLOW_MAX_FILES", 5)
    with pytest.raises(M.NotEvaluable) as e:
        M.follow_shell_calls(root, ["a.sh"])
    assert "budget" in str(e.value) and "NOT EVALUABLE" in str(e.value)


def test_work_budget_exit_code_is_2_through_the_cli(tmp_path, monkeypatch, capsys):
    from hook_integrity_kit import cli
    files = {f"s{i}.sh": f"bash s{i + 1}.sh\n" for i in range(8)}
    files["a.sh"] = "bash s0.sh\n"
    root = _script_project(tmp_path, files)
    monkeypatch.setattr(M, "FOLLOW_MAX_FILES", 3)
    assert cli.main(["bless", "--root", str(root)]) == 2
    out = capsys.readouterr()
    assert "budget" in out.out + out.err and "NOT EVALUABLE" in out.out + out.err
    monkeypatch.setattr(M, "FOLLOW_MAX_FILES", 3000)
    assert cli.main(["bless", "--root", str(root)]) == 0


def test_baseline_file_is_never_hashed_by_a_hook_that_names_it(tmp_path):
    v, b = _bless_tamper_verify(tmp_path, "cat .claude/hook-integrity.json", "h.sh")
    again = run_kit(["verify", "--root", str(tmp_path / "proj")])
    base = json.loads((tmp_path / "proj" / ".claude" / "hook-integrity.json").read_text())
    assert ".claude/hook-integrity.json" not in {f["path"] for f in base["files"]}


def test_settings_command_strings_use_the_same_rule(tmp_path):
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "h.sh").write_text("echo 1\n")
    (root / "cfg.conf").write_text("a=1\n")
    write_settings(root, {"Stop": [{"hooks": [{"type": "command",
                  "command": "sudo -Eu root bash sub/h.sh cfg.conf"}]}]})
    assert run_kit(["bless", "--root", str(root)]).returncode == 0
    (root / "cfg.conf").write_text("a=2\n")
    assert run_kit(["verify", "--root", str(root)]).returncode == 1


def test_a_sourced_shell_helper_is_named(tmp_path):
    root = project(tmp_path, cmd_block("bash ${CLAUDE_PROJECT_DIR}/.claude/hooks/g.sh"))
    (root / ".claude/hooks/g.sh").write_text('set -e\n. "$(dirname "$0")/lib.sh"\nsource x.sh\n')
    bless(root)
    nc = not_checked(M.check(root))
    assert "g.sh" in nc and "source" in nc
