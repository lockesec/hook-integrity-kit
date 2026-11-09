"""A hook that adds a directory built from its own location to ``sys.path`` (the most common
way a Python hook reaches a shared helper) has that directory searched: what it imports from
there is hashed and followed. A path that cannot be worked out from the file alone stays
NOT CHECKED."""
from __future__ import annotations

from conftest import bless, cmd_block, not_checked, project

from hook_integrity_kit import manifest as M

HOOK = ".claude/hooks/g.py"


def setup(tmp_path, hook_src: str, files: dict):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/" + HOOK))
    (root / HOOK).write_text(hook_src)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def hashed(root) -> set:
    return set(M.import_walk(root, [HOOK])[0])


ROOT_CONST = ("import sys\nfrom pathlib import Path\n"
              "ROOT = Path(__file__).resolve().parents[2]\n"
              "sys.path.insert(0, str(ROOT / 'scripts' / 'tools'))\nimport shared\n")


def test_a_directory_built_from_a_module_constant_is_followed(tmp_path):
    root = setup(tmp_path, ROOT_CONST, {"scripts/tools/shared.py": "x = 1\n"})
    assert "scripts/tools/shared.py" in hashed(root)
    bless(root)
    assert "changes sys.path" not in not_checked(M.check(root))
    (root / "scripts/tools/shared.py").write_text("print('changed')\n")
    assert "scripts/tools/shared.py" in M.check(root)["modified"]


def test_the_hooks_own_directory_inserted_is_quiet(tmp_path):
    src = ("import sys\nfrom pathlib import Path\n"
           "sys.path.insert(0, str(Path(__file__).parent))\nimport helper\n")
    root = setup(tmp_path, src, {".claude/hooks/helper.py": "x = 1\n"})
    assert ".claude/hooks/helper.py" in hashed(root)
    bless(root)
    assert "changes sys.path" not in not_checked(M.check(root))


def test_os_path_forms_and_append_are_followed(tmp_path):
    src = ("import os, sys\n"
           "sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))\n"
           "import util\n")
    root = setup(tmp_path, src, {".claude/lib/util.py": "x = 1\n"})
    assert ".claude/lib/util.py" in hashed(root)


def test_a_package_in_the_added_directory_and_its_imports_are_followed(tmp_path):
    files = {"scripts/tools/shared/__init__.py": "from . import io\n",
             "scripts/tools/shared/io.py": "import other\n",
             "scripts/tools/other.py": "y = 2\n"}
    root = setup(tmp_path, ROOT_CONST, files)
    got = hashed(root)
    assert {"scripts/tools/shared/__init__.py", "scripts/tools/shared/io.py",
            "scripts/tools/other.py"} <= got


def test_an_insert_behind_a_condition_is_still_followed(tmp_path):
    src = ("import sys\nfrom pathlib import Path\n_H = Path(__file__).resolve().parents[2]\n"
           "def setup():\n    if str(_H) not in sys.path:\n"
           "        sys.path.insert(0, str(_H / 'scripts' / 'tools'))\n"
           "setup()\nimport shared\n")
    root = setup(tmp_path, src, {"scripts/tools/shared.py": "x = 1\n"})
    assert "scripts/tools/shared.py" in hashed(root)


def test_a_path_from_the_environment_stays_not_checked(tmp_path):
    src = "import os, sys\nsys.path.insert(0, os.environ['LIB'])\nimport util\n"
    root = setup(tmp_path, src, {"lib/util.py": "x = 1\n"})
    bless(root)
    nc = not_checked(M.check(root))
    assert "changes sys.path" in nc and "util" in nc


def test_a_reassigned_constant_is_read_as_every_value_it_can_take(tmp_path):
    src = ("import sys\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
           "ROOT = Path('/opt/elsewhere')\nsys.path.insert(0, str(ROOT))\nimport util\n")
    root = setup(tmp_path, src, {".claude/hooks/util.py": "x = 1\n"})
    assert ".claude/hooks/util.py" in hashed(root)
    bless(root)
    nc = not_checked(M.check(root))
    assert "/opt/elsewhere" in nc and "outside the project" in nc


def test_a_name_bound_by_a_loop_or_a_call_stays_not_checked(tmp_path):
    for src in ("import sys\nfor ROOT in ['a', 'b']:\n    pass\nsys.path.insert(0, ROOT)\nimport u\n",
                "import sys\nROOT = find_root()\nsys.path.insert(0, str(ROOT))\nimport u\n"):
        root = setup(tmp_path / str(abs(hash(src))), src, {})
        bless(root)
        assert "changes sys.path" in not_checked(M.check(root))


def test_one_unfoldable_change_keeps_the_file_named(tmp_path):
    src = ROOT_CONST + "import os\nsys.path.append(os.environ['X'])\n"
    root = setup(tmp_path, src, {"scripts/tools/shared.py": "x = 1\n"})
    assert "scripts/tools/shared.py" in hashed(root)          # what can be followed is
    bless(root)
    assert "changes sys.path" in not_checked(M.check(root))   # and the rest is named


def test_an_added_directory_outside_the_project_is_named(tmp_path):
    src = ("import sys\nfrom pathlib import Path\n"
           "sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'elsewhere'))\n"
           "import util\n")
    root = setup(tmp_path, src, {})
    bless(root)
    nc = not_checked(M.check(root))
    assert "outside the project" in nc and "g.py" in nc


def test_a_name_reassigned_from_itself_is_followed_in_order(tmp_path):
    src = ("import os, sys\nbase = os.path.dirname(__file__)\n"
           "base = os.path.join(base, '..', '..', 'lib')\nsys.path.insert(0, base)\nimport mymod\n")
    root = setup(tmp_path, src, {"lib/mymod.py": "x = 1\n"})
    assert "lib/mymod.py" in M.import_walk(root, [HOOK])[0]


def test_a_name_assigned_in_a_loop_stays_not_checked(tmp_path):
    src = ("import sys\nfrom pathlib import Path\np = Path(__file__).resolve()\n"
           "for _ in range(2):\n    p = p.parent\nsys.path.insert(0, str(p / 'lib'))\nimport mymod\n")
    root = setup(tmp_path, src, {"lib/mymod.py": "x = 1\n"})
    bless(root)
    assert "changes sys.path" in not_checked(M.check(root))


def test_a_module_found_through_sys_path_is_not_also_called_unhashed(tmp_path):
    src = ("import os, sys, importlib\nsys.path.insert(0, os.path.join(os.path.dirname(__file__), "
           "'..', '..', 'lib'))\nimport common\nimportlib.import_module('x')\n")
    root = setup(tmp_path, src, {"lib/common.py": "x = 1\n"})
    walk = M.import_walk(root, [HOOK])
    assert "lib/common.py" in walk[0]
    assert not any("lib/common.py" in n and "not hashed" in n for n in walk[1])
