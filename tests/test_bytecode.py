"""Bytecode caches: a planted or changed .pyc that Python would run is drift, a genuine
cache written after bless is not, and the kit's own bytecode is checked against its source."""
from __future__ import annotations

import importlib.util
import os
import py_compile
import struct

import pytest

from conftest import bless, cmd_block, needs_unreadable, not_checked, project
from hook_integrity_kit import manifest as M


@pytest.fixture
def pyhook(tmp_path):
    root = project(tmp_path, cmd_block("python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/main.py"))
    h = root / ".claude/hooks"
    (h / "main.py").write_text("import helper\n")
    (h / "helper.py").write_text("x = 1\n")
    return root


def _cache(src):
    return importlib.util.cache_from_source(str(src))


def _plant_matching_header(src, evil_source, tmp_path):
    """Compile ``evil_source`` into src's cache file, with a header whose
    mtime and size match ``src`` so the interpreter loads it."""
    evil = tmp_path / "evil_tmp.py"
    evil.write_text(evil_source)
    cfile = _cache(src)
    py_compile.compile(str(evil), cfile=cfile, doraise=True)
    with open(cfile, "rb") as f:
        data = bytearray(f.read())
    st = os.stat(src)
    data[4:8] = struct.pack("<I", 0)
    data[8:16] = struct.pack("<II", int(st.st_mtime) & 0xFFFFFFFF, st.st_size & 0xFFFFFFFF)
    with open(cfile, "wb") as f:
        f.write(bytes(data))
    return cfile


def _foreign_pyc(src, payload=b"payload"):
    cache = src.parent / "__pycache__"
    cache.mkdir(exist_ok=True)
    f = cache / f"{src.stem}.cpython-19.pyc"      # a tag no real interpreter has
    f.write_bytes(b"\0" * 16 + payload)
    return f


def test_a_planted_matching_header_pyc_is_drift(pyhook, tmp_path):
    helper = pyhook / ".claude/hooks/helper.py"
    py_compile.compile(str(helper), cfile=_cache(helper), doraise=True)   # the hook ran once
    bless(pyhook)
    _plant_matching_header(helper, "print('PWNED')\n", tmp_path)
    res = M.check(pyhook)
    assert res["status"] == "drift"
    assert any("helper" in b for b in res["bytecode_changed"]), res


def test_a_planted_pyc_that_appears_after_bless_is_drift(pyhook, tmp_path):
    bless(pyhook)
    _plant_matching_header(pyhook / ".claude/hooks/helper.py", "print('PWNED')\n", tmp_path)
    assert M.check(pyhook)["status"] == "drift"


def test_a_genuine_cache_written_after_bless_is_not_drift(pyhook):
    bless(pyhook)
    helper = pyhook / ".claude/hooks/helper.py"
    py_compile.compile(str(helper), cfile=_cache(helper), doraise=True)
    res = M.check(pyhook)
    assert res["status"] == "clean", res
    assert "helper" not in not_checked(res)


def test_foreign_interpreter_bytecode_changed_since_bless_is_drift(pyhook):
    f = _foreign_pyc(pyhook / ".claude/hooks/helper.py")
    bless(pyhook)
    f.write_bytes(b"\1" * 16 + b"different payload")
    res = M.check(pyhook)
    assert res["status"] == "drift" and res["bytecode_changed"]


def test_foreign_bytecode_header_only_change_is_not_drift(pyhook):
    f = _foreign_pyc(pyhook / ".claude/hooks/helper.py")
    bless(pyhook)
    f.write_bytes(b"\1" * 16 + b"payload")      # a new mtime in the header, same code
    assert M.check(pyhook)["status"] == "clean"


def test_foreign_bytecode_new_since_bless_is_named_not_checked(pyhook):
    bless(pyhook)
    _foreign_pyc(pyhook / ".claude/hooks/helper.py")
    res = M.check(pyhook)
    assert "cpython-19" in not_checked(res), res["not_checked"]


@needs_unreadable
def test_unreadable_bytecode_is_not_evaluable(pyhook):
    helper = pyhook / ".claude/hooks/helper.py"
    py_compile.compile(str(helper), cfile=_cache(helper), doraise=True)
    bless(pyhook)
    os.chmod(_cache(helper), 0)
    try:
        assert M.check(pyhook)["status"] == "error"
    finally:
        os.chmod(_cache(helper), 0o644)


def test_kit_bytecode_that_does_not_match_its_source_is_reported(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text("x = 1\n")
    py_compile.compile(str(pkg / "mod.py"), cfile=_cache(pkg / "mod.py"), doraise=True)
    assert M.kit_bytecode_mismatches(pkg) == []
    _plant_matching_header(pkg / "mod.py", "x = 2\n", tmp_path)
    assert M.kit_bytecode_mismatches(pkg) == [f"pkg/__pycache__/{os.path.basename(_cache(pkg / 'mod.py'))}"]
