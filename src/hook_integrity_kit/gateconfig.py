"""``check-gate-config``: an agent must not weaken the gate it is failing.

The cheapest way to make a failing lint pass is to edit the lint's config: add an
``ignore =`` line to ``ruff.toml`` instead of fixing the violation. This hook
refuses Write/Edit/MultiEdit calls that MODIFY an existing gate config.

Adapted from ``scripts/hooks/config-protection.js`` in everything-claude-code
(ECC, https://github.com/affaan-m/ECC, MIT License, Copyright (c) 2026 Affaan
Mustafa; see NOTICE). Taken from it:

* the idea itself, and the basename list of linter/formatter configs;
* first-time creation is allowed: a gate that does not exist yet cannot be
  gamed, and scaffolding a config into a fresh project is legitimate. Ours: creation
  is refused when the same tool already has a config here or in a parent directory,
  because a new file can outrank it (``pytest.ini`` beats ``pyproject.toml``);
* ``pyproject.toml`` is deliberately NOT protected: it mixes project metadata
  with lint config, and blocking it would block ordinary dependency work. The same
  goes for ``setup.cfg``, and for ``conftest.py``, which is test code;
* case-insensitive basename matching (on case-insensitive filesystems
  ``RUFF.TOML`` is the same file as ``ruff.toml``);
* existence is judged with ``lstat``: a dangling symlink at a protected name
  still counts as an existing config, and any stat error other than
  "not found" counts as existing, so an error can never switch the guard off;
* a payload too large to parse is refused rather than passed unexamined.

Ours: the Python port, the per-entry reasons, the extra entries marked below,
the operator override, and the config-file extension points.

Escape hatch: the OPERATOR sets ``HOOK_KIT_GATE_CONFIG_OVERRIDE=1`` in the
environment Claude Code runs in. The hook reads its own process environment,
which an agent's Bash calls do not change, so an agent cannot grant itself the
override mid-session.

Known limit: this sees Write/Edit/MultiEdit only. ``echo ... >> ruff.toml``
through Bash is a different lane.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Dict, Optional

from . import config as cfgmod
from . import hookio

OVERRIDE_ENV = "HOOK_KIT_GATE_CONFIG_OVERRIDE"

_LINT = "linter/formatter config: weakening it is not fixing the code"

#: basename (lower case) -> reason
DEFAULT_PROTECTED: Dict[str, str] = {
    # From ECC's PROTECTED_FILES.
    **{name: _LINT for name in (
        ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yml",
        ".eslintrc.yaml", "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
        "eslint.config.ts", "eslint.config.mts", "eslint.config.cts",
        ".prettierrc", ".prettierrc.js", ".prettierrc.cjs", ".prettierrc.json",
        ".prettierrc.yml", ".prettierrc.yaml", "prettier.config.js", "prettier.config.cjs",
        "prettier.config.mjs", "biome.json", "biome.jsonc", ".shellcheckrc",
        ".stylelintrc", ".stylelintrc.json", ".stylelintrc.yml",
        ".markdownlintrc",
        # Ours: spellings the same tools read.
        ".eslintignore", ".eslintrc.mjs", ".prettierignore", ".prettierrc.toml", ".prettierrc.json5",
        ".prettierrc.mjs", "prettier.config.ts", ".stylelintrc.js", ".stylelintrc.cjs",
        ".stylelintrc.yaml", "stylelint.config.js", "stylelint.config.cjs", "stylelint.config.mjs",
        ".stylelintignore", ".markdownlint.jsonc", ".markdownlint.yml", ".markdownlint-cli2.jsonc",
        ".markdownlintignore")},
    "ruff.toml": "lint gate: ignore-list edits defeat the lint",
    ".ruff.toml": "lint gate",
    ".markdownlint.json": "docs lint gate",
    ".markdownlint.yaml": "docs lint gate",
    # Ours.
    "pytest.ini": "test configuration: discovery and markers decide what runs",
    ".pytest.ini": "test configuration: discovery and markers decide what runs",
    "tox.ini": "test configuration: it can hold pytest and flake8 settings",
    ".coveragerc": "coverage gate: omit lists decide what counts",
    ".mypy.ini": "type-check gate",
    ".importlinter": "architectural import contracts",
    ".flake8": "lint gate",
    "mypy.ini": "type-check gate",
    ".pre-commit-config.yaml": "pre-commit gate: the checks that run before every commit",
}


#: tool -> (file names, (shared file, text that shows it holds this tool's settings), ...)
_TOOLS = (
    (("pytest.ini", ".pytest.ini", "tox.ini"),
     (("pyproject.toml", "[tool.pytest"), ("setup.cfg", "[tool:pytest]"))),
    (("ruff.toml", ".ruff.toml"), (("pyproject.toml", "[tool.ruff"),)),
    (("mypy.ini", ".mypy.ini"), (("pyproject.toml", "[tool.mypy"), ("setup.cfg", "[mypy"))),
    ((".flake8", "tox.ini"), (("setup.cfg", "[flake8]"),)),
    ((".coveragerc",), (("pyproject.toml", "[tool.coverage"), ("setup.cfg", "[coverage:"))),
    ((".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.mjs", ".eslintrc.json", ".eslintrc.yml",
      ".eslintrc.yaml", "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
      "eslint.config.ts", "eslint.config.mts", "eslint.config.cts"),
     (("package.json", '"eslintConfig"'),)),
    ((".prettierrc", ".prettierrc.js", ".prettierrc.cjs", ".prettierrc.mjs", ".prettierrc.json",
      ".prettierrc.json5", ".prettierrc.yml", ".prettierrc.yaml", ".prettierrc.toml",
      "prettier.config.js", "prettier.config.cjs", "prettier.config.mjs", "prettier.config.ts"),
     (("package.json", '"prettier"'),)),
    ((".stylelintrc", ".stylelintrc.js", ".stylelintrc.cjs", ".stylelintrc.json", ".stylelintrc.yml",
      ".stylelintrc.yaml", "stylelint.config.js", "stylelint.config.cjs", "stylelint.config.mjs"),
     (("package.json", '"stylelint"'),)),
    (("biome.json", "biome.jsonc"), ()),
    ((".markdownlintrc", ".markdownlint.json", ".markdownlint.jsonc", ".markdownlint.yaml",
      ".markdownlint.yml", ".markdownlint-cli2.jsonc"), ()),
)


def held_elsewhere(path: Path, stop: Optional[Path]) -> Optional[str]:
    """The config that creating ``path`` would sit beside or outrank: the same tool's config
    in its directory or a parent, up to the project root. None if the tool has none."""
    name = path.name.lower()
    tools = [t for t in _TOOLS if name in t[0]]
    if not tools:
        return None
    start = Path(os.path.abspath(path)).parent
    stop = Path(os.path.abspath(stop)) if stop else None
    if stop is not None and stop != start and stop not in start.parents:
        stop = None                                    # outside the project: this directory only
    for d in [start, *start.parents]:
        for names, shared in tools:
            for n in names:
                if exists_for_guard(d / n):        # `path` itself is absent: this is another file
                    return str(d / n)
            for fname, mark in shared:
                try:
                    with open(d / fname, encoding="utf-8", errors="replace") as fh:
                        if mark in fh.read(1024 * 1024):
                            return f"{d / fname} ({mark})"
                except OSError:
                    continue
        if stop is None or d == stop:
            break
    return None


def linked_gate(path: Path, protected: Dict[str, str], stop: Optional[Path]) -> Optional[str]:
    """The protected config ``path`` is a hard link to, if it sits in the same directory or a
    parent. A hard link is the same file under another name, as `check-write` holds for settings."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_nlink < 2:
        return None
    start = Path(os.path.abspath(path)).parent
    stop = Path(os.path.abspath(stop)) if stop else None
    for d in [start, *start.parents]:
        for n in protected:
            try:
                cs = os.stat(d / n)
            except OSError:
                continue
            if (cs.st_dev, cs.st_ino) == (st.st_dev, st.st_ino):
                return n
        if stop is None or d == stop:
            break
    return None


def protected_map(cfg: dict) -> Dict[str, str]:
    sec = cfgmod.section(cfg, "gate_config")
    disabled = {d.lower() for d in cfgmod.str_list(sec, "disable")}
    out = {k: v for k, v in DEFAULT_PROTECTED.items() if k not in disabled}
    extra = sec.get("extra_protected")
    if isinstance(extra, dict):
        for name, reason in extra.items():
            if isinstance(name, str) and name.strip():
                out[name.strip().lower()] = str(reason or "project gate config")
    return out


def reason_for(file_path: str, protected: Dict[str, str]) -> Optional[str]:
    name = Path(file_path.replace("\\", "/")).name
    return protected.get(name) or protected.get(name.lower())


def exists_for_guard(path: Path) -> bool:
    """True unless the path is genuinely absent (see the module docstring)."""
    try:
        os.lstat(path)
        return True
    except OSError as e:
        return e.errno != errno.ENOENT


def run(payload: Optional[dict], oversized: bool, cfg: dict) -> int:
    if oversized:
        return hookio.deny(f"GATE-CONFIG PROTECTION: {hookio.refusal_reason(oversized)}; "
                           "refusing rather than passing it unexamined.")
    if payload is None or payload.get("tool_name") not in ("Write", "Edit", "MultiEdit"):
        return hookio.EXIT_ALLOW
    ti = hookio.tool_input(payload)
    fp = ti.get("file_path") or ti.get("file") or ""
    if not isinstance(fp, str) or not fp:
        return hookio.EXIT_ALLOW
    protected = protected_map(cfg)
    path = Path(fp)
    if not path.is_absolute() and isinstance(payload.get("cwd"), str):
        path = Path(payload["cwd"]) / path
    # Judged as written AND as the file the write would land in: an innocently named
    # symlink to ruff.toml is ruff.toml.
    reason = reason_for(fp, protected)
    if reason is None:
        try:
            reason = reason_for(os.path.realpath(path), protected)
        except (OSError, ValueError):
            reason = None
    project = cfgmod.project_dir(payload)
    if reason is None:
        linked = linked_gate(path, protected, project)
        if linked is None:
            return hookio.EXIT_ALLOW
        reason = f"a hard link to {linked}: {protected[linked]}"
    name = Path(fp).name
    if not exists_for_guard(path):
        held = held_elsewhere(path, project)
        if held is None:
            return hookio.EXIT_ALLOW                   # first-time creation
        if os.environ.get(OVERRIDE_ENV) == "1":
            return hookio.nudge(f"Gate-config override active: creating {name} beside {held} is "
                                f"allowed by {OVERRIDE_ENV}=1. Say in the commit message why.")
        return hookio.deny(
            f"BLOCKED: a new {name} would sit beside or outrank the gate already held in {held} "
            f"({reason}). Fix the flagged code instead. If the gate itself must change, ask the "
            f"user, or have the operator set {OVERRIDE_ENV}=1 for this session.")
    if os.environ.get(OVERRIDE_ENV) == "1":
        return hookio.nudge(f"Gate-config override active: the edit to {name} is allowed "
                            f"by {OVERRIDE_ENV}=1. Say in the commit message why the gate moved.")
    return hookio.deny(
        f"BLOCKED: {name} is a GATE CONFIG ({reason}). Weakening a check is not fixing a "
        f"violation; fix the flagged code instead. If the gate itself must change, ask the "
        f"user, or have the operator set {OVERRIDE_ENV}=1 for this session.")
