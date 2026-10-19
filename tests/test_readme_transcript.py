"""The README quick-start transcript is real output: every line of its console block (bar the
prompt lines) appears, in order, in what examples/demo.sh prints. Without this check the
transcript went stale once."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent


def _console_lines() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"## Quick start.*?```console\n(.*?)```", text, re.S)
    assert m, "README quick start has no console block"
    return [ln for ln in m.group(1).splitlines() if ln.strip() and not ln.startswith("$ ")
            and ln.strip() != "1"]


def test_readme_transcript_matches_the_demo(tmp_path):
    exe = Path(sys.executable).parent
    if not (exe / "hook-integrity-kit").exists() and not shutil.which("hook-integrity-kit"):
        pytest.skip("hook-integrity-kit console script is not installed in this venv")
    env = dict(os.environ, HOME=str(tmp_path), PATH=f"{exe}{os.pathsep}{os.environ['PATH']}")
    out = subprocess.run(["sh", str(ROOT / "examples" / "demo.sh")], env=env, capture_output=True,
                         text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-500:]
    lines = (out.stdout + out.stderr).splitlines()
    pos = 0
    for want in _console_lines():
        while pos < len(lines) and lines[pos].rstrip() != want.rstrip():
            pos += 1
        assert pos < len(lines), f"README line not in the demo output (in order): {want!r}"
        pos += 1


def test_the_opening_console_block_is_an_excerpt_of_the_quick_start_transcript():
    """The first screen shows real `verify` output; every line must also be in the checked
    quick-start block, so it cannot drift from what the tool prints."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    first = re.search(r"```console\n(.*?)```", text, re.S).group(1)
    assert text.index(first) < text.index("## Quick start")
    quick = _console_lines()
    for ln in first.splitlines():
        if ln.strip() and not ln.startswith("$ "):
            assert ln.rstrip() in [q.rstrip() for q in quick], ln


def test_every_example_directory_carries_a_synthetic_data_marker():
    """CONTRIBUTING promises this; fixtures here are invented and must say so."""
    for d in sorted((ROOT / "examples").iterdir()):
        if d.is_dir() and d.name != "__pycache__":
            assert (d / "SYNTHETIC-DATA").is_file(), f"examples/{d.name} has no SYNTHETIC-DATA"
