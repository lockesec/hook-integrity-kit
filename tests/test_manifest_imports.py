"""Modules a registered hook imports. The import walk is followed and hashed, including
through symlinked packages; whatever the finder resolves first is what is hashed; dynamic
imports and sys.path or import-machinery changes are named NOT CHECKED; an unparseable or
unreadable helper is NOT EVALUABLE."""
from __future__ import annotations

import json
import os
import py_compile
import sys

import pytest

from conftest import (
    bless, cmd_block, entry, hooks_block, needs_unreadable, not_checked, paths, project,
    project_from_files, run_kit, settings_with,
)
from hook_integrity_kit import manifest as M


def fixture(tmp_path, link=True):
    root = tmp_path / "r"
    hooks = root / ".claude" / "hooks"
    pkg = hooks / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    shared = root / "shared"
    shared.mkdir()
    (shared / "__init__.py").write_text("")
    (shared / "helper.py").write_text('print("BEFORE")\n')
    if link:
        (pkg / "sub").symlink_to(shared, target_is_directory=True)
    (hooks / "main.py").write_text("import pkg.sub.helper\n")
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": {
        "SessionStart": [{"hooks": [{"type": "command",
                                     "command": "python3 .claude/hooks/main.py"}]}]}}))
    return root, pkg, shared


def _bless(root, *extra):
    return run_kit(["bless", "--root", str(root), *extra])


def _verify(root, *extra):
    return run_kit(["verify", "--root", str(root), *extra])


DYNAMIC = [
    "from importlib import import_module\nimport_module('helper')\n",
    "from importlib import import_module as im\nim('helper')\n",
    "import importlib.util as u\ns = u.spec_from_file_location('h', 'h.py')\nm = u.module_from_spec(s)\n"
    "s.loader.exec_module(m)\n",
    "from importlib.util import spec_from_file_location\nspec_from_file_location('h', 'h.py')\n",
    "import importlib.machinery\nimportlib.machinery.SourceFileLoader('h', 'h.py').load_module()\n",
    "from importlib.machinery import SourceFileLoader as L\nL('h', 'h.py')\n",
    "import runpy\nrunpy.run_module('helper')\n",
    "import runpy\nrunpy.run_path('helper.py')\n",
    "from runpy import run_path\nrun_path('helper.py')\n",
    "import builtins\nbuiltins.__import__('helper')\n",
    "exec(compile(open('helper.py').read(), 'helper.py', 'exec'))\n",
    "src = open('helper.py').read()\nexec(src)\n",
    "from pathlib import Path\nexec(Path('helper.py').read_text())\n",
    "f = __import__\nf('helper')\n",
]


def plugin(root, hooks, name="p", base=".claude/plugins"):
    proot = root / base / name
    (proot / "hooks").mkdir(parents=True, exist_ok=True)
    (proot / "hooks" / "hooks.json").write_text(json.dumps({"hooks": hooks}))
    return proot


@pytest.fixture
def pyhook(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    h = root / ".claude/hooks"
    (h / "main.py").write_text("import helper\n")
    (h / "helper.py").write_text("x = 1\n")
    return root


@pytest.fixture
def stdlib_importer(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    (root / ".claude/hooks/main.py").write_text("import json\n")
    return root


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
def test_an_unreadable_imported_helper_is_not_evaluable(tmp_path):
    root = tmp_path / "r"
    (root / ".claude/hooks").mkdir(parents=True)
    (root / ".claude/hooks/a.py").write_text("import helper\n")
    (root / ".claude/hooks/helper.py").write_text("x = 1\n")
    settings_with(root, entry("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/a.py"))
    bless(root)
    (root / ".claude/hooks/helper.py").chmod(0)
    try:
        res = M.check(root)
    finally:
        (root / ".claude/hooks/helper.py").chmod(0o600)
    assert res["status"] == "error" and "helper.py" in res["error"]


def test_regular_package_control_reports_drift(tmp_path):
    root, pkg, _ = fixture(tmp_path)
    bless(root)
    (pkg / "control.py").write_text("x = 1\n")
    assert M.check(root)["status"] != "clean"


def test_symlinked_subpackage_file_is_in_baseline(tmp_path):
    root, _, _ = fixture(tmp_path)
    got = {f["path"] for f in bless(root)["files"]}
    assert ".claude/hooks/pkg/sub/helper.py" in got


def test_edit_behind_directory_symlink_is_drift(tmp_path):
    root, _, shared = fixture(tmp_path)
    bless(root)
    (shared / "helper.py").write_text('print("AFTER")\n')
    res = M.check(root)
    assert res["status"] != "clean"


def test_unchanged_symlinked_subpackage_is_clean(tmp_path):
    root, _, _ = fixture(tmp_path)
    bless(root)
    res = M.check(root)
    assert res["status"] == "clean"
    assert not res["not_checked"] or all("symlink" not in n for n in res["not_checked"])


def test_symlink_loop_terminates_and_is_named(tmp_path):
    root, pkg, _ = fixture(tmp_path, link=False)
    (pkg / "loop").symlink_to(pkg, target_is_directory=True)
    (root / ".claude" / "hooks" / "main.py").write_text("import pkg\n")
    base = bless(root)
    assert any("symlink loop" in n for n in M.check(root)["not_checked"])
    assert ".claude/hooks/pkg/__init__.py" in {f["path"] for f in base["files"]}


def test_symlink_to_outside_project_is_not_checked_not_clean(tmp_path):
    root, pkg, shared = fixture(tmp_path, link=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "__init__.py").write_text("")
    (outside / "helper.py").write_text("x = 1\n")
    (pkg / "sub").symlink_to(outside, target_is_directory=True)
    bless(root)
    (outside / "helper.py").write_text("x = 2\n")
    res = M.check(root)
    assert any("outside the project" in n and "sub" in n for n in res["not_checked"])


def test_normal_nested_package_still_walked(tmp_path):
    root, pkg, _ = fixture(tmp_path, link=False)
    (pkg / "inner").mkdir()
    (pkg / "inner" / "__init__.py").write_text("")
    (pkg / "inner" / "m.py").write_text("y = 1\n")
    got = {f["path"] for f in bless(root)["files"]}
    assert ".claude/hooks/pkg/inner/m.py" in got


@pytest.mark.parametrize("src", DYNAMIC)
def test_dynamic_import_shapes_are_named_not_checked(tmp_path, src):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": src, ".claude/hooks/helper.py": "x = 1\n"},
                    hooks_block(".claude/hooks/a.py"))
    notes = M.import_walk(root, [".claude/hooks/a.py"])[1]
    assert any("a.py" in n and "dynamically" in n for n in notes), notes


STATIC = [
    "import json\nprint(json.dumps({}))\n",
    "from pathlib import Path\nprint(Path('x').name)\n",
    "import importlib.metadata\nprint(1)\n",
    "exec('x = 1')\n",
]


@pytest.mark.parametrize("src", STATIC)
def test_static_files_get_no_dynamic_import_note(tmp_path, src):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": src}, hooks_block(".claude/hooks/a.py"))
    assert M.import_walk(root, [".claude/hooks/a.py"])[1] == []


def test_verify_prints_the_not_checked_line_for_a_dynamic_import(tmp_path):
    root = project_from_files(tmp_path, {".claude/hooks/a.py": DYNAMIC[0]}, hooks_block(".claude/hooks/a.py"))
    assert _bless(root).returncode == 0
    r = _verify(root)
    assert r.returncode == 0 and "NOT CHECKED" in r.stdout and "dynamically" in r.stdout


MUTATIONS = [
    "sys.path[:] = ['lib'] + sys.path", "sys.path[0:0] = ['lib']", "sys.path[0] = 'lib'",
    "sys.path.__iadd__(['lib'])", "sys.path += ['lib']", "sys.path = ['lib'] + sys.path",
    "sys.path.insert(0, 'lib')", "sys.path.append('lib')", "sys.path.extend(['lib'])",
    "p = sys.path\np.insert(0, 'lib')", "p = sys.path\np[:] = ['lib']",
    "sys.meta_path.insert(0, object())", "sys.meta_path.append(object())",
    "sys.path_hooks.append(object())", "sys.path_hooks[:] = []",
    "sys.meta_path = []", "del sys.path[0]", "sys.path.pop(0)", "sys.path.remove('x')",
    "sys.path.clear()", "sys.path.reverse()", "sys.path.sort()",
    "import sys as s\ns.path[0:0] = ['lib']", "import sys as s\ns.path.insert(0, 'lib')",
    "from sys import path\npath.insert(0, 'lib')", "from sys import path\npath[:] = []",
    "from sys import path as P\nP.append('lib')", "from sys import path\npath += ['lib']",
    "from sys import meta_path\nmeta_path.append(object())",
    "from sys import path_hooks as H\nH.append(object())",
    "s = sys\ns.path.append('lib')", "getattr(sys, 'path').append('lib')",
    "setattr(sys, 'path', ['lib'])", "sys.__dict__['path'] = ['lib']", "vars(sys)['path'] = []",
    "mutate(sys.path)", "x = [sys.path]", "sys.path.__setitem__(0, 'lib')",
    "import imp\nimp.load_source('m', 'lib/m.py')", "import imp\nimp.load_module('m', 0, 'p', 0)",
    "from imp import load_source\nload_source('m', 'x')",
]


@pytest.mark.parametrize("stmt", MUTATIONS)
def test_every_path_and_import_machinery_mutation_is_dynamic(stmt):
    tree = __import__("ast").parse("import sys, os\n" + stmt + "\nimport json\n")
    assert M._imports(tree)[1] is True, stmt


PLAIN_READS = [
    "print(sys.path)", "x = sys.path[0]", "n = len(sys.path)", "ok = 'lib' in sys.path",
    "for p in sys.path:\n    print(p)", "print(sys.argv, sys.exit)", "d = os.path.join('a', 'b')",
    "print(sorted(sys.path))", "print(sys.platform)",
]


@pytest.mark.parametrize("stmt", PLAIN_READS)
def test_plain_reads_of_sys_path_are_not_dynamic(stmt):
    tree = __import__("ast").parse("import sys, os\n" + stmt + "\nimport json\n")
    assert M._imports(tree)[1] is False, stmt


def test_end_to_end_shadow_attack_via_sys_path_slice_is_not_a_plain_ok(tmp_path):
    root = project_from_files(tmp_path, {
        ".claude/hooks/h.py": "import sys\nsys.path[0:0] = ['.claude/hooks/lib']\nimport json\n",
        ".claude/hooks/lib/json.py": "x = 1\n"}, hooks_block(".claude/hooks/h.py"))
    assert _bless(root).returncode == 0
    (root / ".claude/hooks/lib/json.py").write_text("import os\nos.system('echo owned')\n")
    v = _verify(root)
    assert "NOT CHECKED" in v.stdout, v.stdout
    assert "json" in v.stdout and "lib/json.py" in v.stdout, v.stdout
    b = _bless(root)
    assert "NOT CHECKED" in b.stdout and "lib/json.py" in b.stdout


def test_stdlib_name_that_exists_as_a_project_file_is_named_when_the_path_changes(tmp_path):
    root = project_from_files(tmp_path, {
        ".claude/hooks/h.py": "import sys\nsys.path.insert(0, 'x')\nimport json, os\n",
        "x/json.py": "y = 1\n"}, hooks_block(".claude/hooks/h.py"))
    _, notes, _ = M.import_walk(root, [".claude/hooks/h.py"])
    assert any("json" in n and "x/json.py" in n for n in notes), notes
    assert not any("x/os.py" in n for n in notes)


@pytest.mark.parametrize("src", [
    "import sys\nsys.__dict__['path'].insert(0, 'x')",
    "import sys\nglobals()['sys'].path.insert(0, 'x')",
    "import os\nos.sys.path.insert(0, 'x')",
    "from sys import *\npath.insert(0, 'x')",
])
def test_sys_path_by_another_name_is_dynamic(src):
    import ast
    assert M._imports(ast.parse(src))[1] is True


@pytest.mark.parametrize("src", [
    "import sys\nm = sys.modules.get('json')",
    "import sys\nprint(len(sys.path))",
    "import sys\nks = list(sys.modules.keys())",
])
def test_plain_reads_of_sys_path_by_another_name_are_not_dynamic(src):
    import ast
    assert M._imports(ast.parse(src))[1] is False


def test_plugin_python_hook_sibling_helper_is_hashed(tmp_path):
    root = project(tmp_path)
    proot = plugin(root, cmd_block("python3 ${CLAUDE_PLUGIN_ROOT}/hooks/main.py"))
    (proot / "hooks" / "main.py").write_text("import helper\n")
    (proot / "hooks" / "helper.py").write_text("x = 1\n")
    base = bless(root)
    assert ".claude/plugins/p/hooks/helper.py" in paths(base)
    (proot / "hooks" / "helper.py").write_text("print('changed')\n")
    res = M.check(root)
    assert res["status"] == "drift" and res["modified"] == [".claude/plugins/p/hooks/helper.py"]


def test_a_stdlib_import_with_nothing_beside_it_is_clean_and_quiet(stdlib_importer):
    bless(stdlib_importer)
    res = M.check(stdlib_importer)
    assert res["status"] == "clean" and "json" not in not_checked(res)


@pytest.mark.parametrize("plant", ["package", "sourceless_pyc", "extension", "source"])
def test_a_sibling_that_shadows_a_stdlib_import_is_drift(stdlib_importer, plant):
    h = stdlib_importer / ".claude/hooks"
    bless(stdlib_importer)
    if plant == "package":
        (h / "json").mkdir()
        (h / "json" / "__init__.py").write_text("print('PWNED')\n")
    elif plant == "sourceless_pyc":
        s = h / "_tmp.py"
        s.write_text("print('PWNED')\n")
        py_compile.compile(str(s), cfile=str(h / "json.pyc"), doraise=True)
        s.unlink()
    elif plant == "extension":
        (h / "json.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF fake")
    else:
        (h / "json.py").write_text("print('PWNED')\n")
    res = M.check(stdlib_importer)
    assert res["status"] == "drift" and res["added"], res


def test_a_helper_package_is_hashed_and_a_change_inside_it_is_drift(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    h = root / ".claude/hooks"
    (h / "main.py").write_text("from lib import util\n")
    (h / "lib").mkdir()
    (h / "lib" / "__init__.py").write_text("")
    (h / "lib" / "util.py").write_text("x = 1\n")
    base = bless(root)
    assert ".claude/hooks/lib/util.py" in paths(base)
    (h / "lib" / "util.py").write_text("print('changed')\n")
    assert M.check(root)["modified"] == [".claude/hooks/lib/util.py"]


@needs_unreadable
def test_an_unreadable_package_file_is_not_evaluable(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    h = root / ".claude/hooks"
    (h / "main.py").write_text("import lib\n")
    (h / "lib").mkdir()
    (h / "lib" / "__init__.py").write_text("import os\n")
    bless(root)
    os.chmod(h / "lib" / "__init__.py", 0)
    try:
        assert M.check(root)["status"] == "error"
    finally:
        os.chmod(h / "lib" / "__init__.py", 0o644)


def test_a_same_content_symlink_that_moves_sys_path_is_drift(pyhook):
    bless(pyhook)
    h = pyhook / ".claude/hooks"
    target = pyhook / "node_modules/.cache/x"
    target.mkdir(parents=True)
    (target / "main.py").write_text("import helper\n")
    (target / "helper.py").write_text("print('PWNED')\n")
    (h / "main.py").unlink()
    os.symlink(target / "main.py", h / "main.py")
    res = M.check(pyhook)
    assert res["status"] == "drift", res
    assert ".claude/hooks/main.py" in res["modified"]
    # the helper Python now loads sits beside the link TARGET
    assert "node_modules/.cache/x/helper.py" in res["added"], res


def test_a_symlinked_entry_point_retarget_is_drift(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    for d in ("a", "b"):
        (root / d).mkdir()
        (root / d / "main.py").write_text("print('same')\n")
    os.symlink(root / "a" / "main.py", root / ".claude/hooks/main.py")
    bless(root)
    os.unlink(root / ".claude/hooks/main.py")
    os.symlink(root / "b" / "main.py", root / ".claude/hooks/main.py")
    assert ".claude/hooks/main.py" in M.check(root)["modified"]


@pytest.mark.parametrize("how", ["interpreter", "shebang"])
def test_an_extensionless_python_hook_has_its_imports_followed(tmp_path, how):
    command = ("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/guard" if how == "interpreter"
               else "${CLAUDE_PROJECT_DIR}/.claude/hooks/guard")
    root = project(tmp_path, cmd_block(command))
    h = root / ".claude/hooks"
    head = "" if how == "interpreter" else "#!/usr/bin/env python3\n"
    (h / "guard").write_text(head + "import helper\n")
    (h / "helper.py").write_text("x = 1\n")
    bless(root)
    (h / "helper.py").write_text("print('changed')\n")
    assert M.check(root)["modified"] == [".claude/hooks/helper.py"]


def test_a_data_file_passed_to_a_python_hook_is_not_parsed_as_python(tmp_path):
    root = project(tmp_path, cmd_block(
        "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/h.py ${CLAUDE_PROJECT_DIR}/conf.json"))
    (root / ".claude/hooks/h.py").write_text("print(1)\n")
    (root / "conf.json").write_text("{not python")
    bless(root)
    assert M.check(root)["status"] == "clean"


def test_a_sys_path_change_is_named(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/g.py"))
    (root / ".claude/hooks/g.py").write_text("import sys\nsys.path.insert(0, 'lib')\nimport util\n")
    bless(root)
    nc = not_checked(M.check(root))
    assert "changes sys.path" in nc and "util" in nc


def test_an_import_that_resolves_outside_the_hook_dir_is_named(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/g.py"))
    (root / ".claude/hooks/g.py").write_text("import os, json\nimport some_third_party_pkg\n")
    bless(root)
    nc = not_checked(M.check(root))
    assert "some_third_party_pkg" in nc and "json" not in nc and " os" not in nc


@pytest.mark.parametrize("which", ["entry", "helper"])
def test_an_unparseable_python_file_is_not_evaluable(tmp_path, which):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    h = root / ".claude/hooks"
    (h / "main.py").write_text("import helper\n")
    (h / "helper.py").write_text("x = 1\n")
    bless(root)
    (h / ("main.py" if which == "entry" else "helper.py")).write_text(
        "import helper\ndef broken(:\n")
    res = M.check(root)
    assert res["status"] == "error", res
    assert "parse" in res["error"] and f"{sys.version_info[0]}.{sys.version_info[1]}" in res["error"]


def test_an_unparseable_python_file_fails_bless(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    (root / ".claude/hooks/main.py").write_text("def broken(:\n")
    r = run_kit(["bless", "--root", str(root)])
    assert r.returncode == 2 and "parse" in r.stderr
