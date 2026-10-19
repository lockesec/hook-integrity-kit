"""The optional project config file, ``.claude/hook-integrity-kit.json``.

JSON rather than TOML so the kit stays standard-library only on Python 3.9 and
3.10, which have no ``tomllib``.

Design rule: **a broken config can never weaken the defaults.** An unreadable or
malformed file is ignored with a warning on stderr, so the guards fall back to
their built-in rules. A config can add rules and switch named default rules
off; a config the kit cannot read does neither.

The file lives in the project, so an agent could try to edit it to switch a rule
off. ``check-write`` refuses Write/Edit calls on it by default, and ``bless``
hashes it, so an edit that slips past shows up as drift.

Shape (every key optional)::

    {
      "commands":    {"extra_rules": [{"id": "...", "pattern": "...",
                                        "description": "...", "severity": "HIGH"}],
                      "disable": ["rule-id"],
                      "protected_branches": ["main", "master", "release"],
                      "sql_tools": {"mcp__db__query": "sql"}},
      "writes":      {"extra_block": [{"id": "...", "pattern": "...", "description": "..."}],
                      "extra_warn":  [{"id": "...", "pattern": "...", "description": "..."}],
                      "disable": ["rule-id"],
                      "agent_scopes": {"researcher": ["notes/**", "/tmp/scratch-*/**"]}},
      "gate_config": {"extra_protected": {"my-lint.cfg": "why it is a gate"},
                      "disable": ["pytest.ini"]},
      "integrity":   {"extra_files": ["tools/policy/*.json"]},
      "profiles":    {"tiers": {"my_hook": "strict"}, "always_on": ["my_guard"]}
    }
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

CONFIG_REL = Path(".claude") / "hook-integrity-kit.json"


def project_dir(payload: Optional[dict] = None) -> Optional[Path]:
    """The project a hook is running for: ``$CLAUDE_PROJECT_DIR`` (set by Claude
    Code for hook processes), else the payload's ``cwd``, else None."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env)
    cwd = (payload or {}).get("cwd")
    if isinstance(cwd, str) and cwd:
        return Path(cwd)
    return None


def load(path: Optional[Path] = None, project: Optional[Path] = None,
         warn=None) -> dict:
    """Load the config. Missing -> {}. Unreadable or not an object -> {} plus a
    warning (never an exception: a guard must not crash on its own config)."""
    warn = warn or (lambda msg: print(f"hook-integrity-kit: {msg}", file=sys.stderr))
    if path is None:
        if project is None:
            return {}
        path = project / CONFIG_REL
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        warn(f"config {path} unreadable ({e}); using the built-in defaults")
        return {}
    if not isinstance(data, dict):
        warn(f"config {path} is not a JSON object; using the built-in defaults")
        return {}
    validate(data, warn)
    return data


SECTIONS = ("commands", "writes", "gate_config", "integrity", "profiles")


def _is_regex(pattern: object) -> Optional[str]:
    """None if ``pattern`` is a usable regular expression, else why not."""
    import re
    if not isinstance(pattern, str):
        return "'pattern' must be a string"
    try:
        re.compile(pattern)
    except re.error as e:
        return f"bad regex ({e})"
    return None


def _check_rules(sec: dict, section: str, key: str, warn) -> None:
    raw = sec.get(key)
    if raw is None:
        return
    if not isinstance(raw, list):
        warn(f"{section}.{key} must be a list of objects, not {type(raw).__name__}; "
             "the whole list is ignored")
        return
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            warn(f"{section}.{key}[{i}] skipped: must be an object with a 'pattern'")
            continue
        why = _is_regex(entry.get("pattern"))
        if why:
            warn(f"{section}.{key}[{i}] skipped: {why}")


def _check_str_list(sec: dict, section: str, key: str, warn, known=None, fold=False) -> None:
    raw = sec.get(key)
    if raw is None:
        return
    if not isinstance(raw, list):
        warn(f"{section}.{key} must be a list of strings, not {type(raw).__name__}; "
             "the whole list is ignored")
        return
    for i, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            warn(f"{section}.{key}[{i}] ignored: must be a non-empty string")
        elif known is not None and (item.lower() if fold else item) not in known:
            warn(f"{section}.{key}[{i}] names '{item}', which is not a known id; it "
                 "disables nothing")


def validate(cfg: dict, warn) -> None:
    """Name, on stderr, every config entry the kit will not use: a section that is not
    an object, a list that is not a list, a regex that does not compile, an id that
    names no rule. The entry is skipped exactly as before (a broken config never
    weakens the defaults); this only stops it being skipped SILENTLY."""
    from . import commands, gateconfig, writes
    for key in cfg:
        if key not in SECTIONS and not (isinstance(key, str) and key.startswith(("_", "$", "//"))):
            warn(f"unknown top-level key '{key}' ignored (sections: {', '.join(SECTIONS)})")
    for name in SECTIONS:
        if name in cfg and not isinstance(cfg[name], dict):
            warn(f"{name} must be an object, not {type(cfg[name]).__name__}; "
                 "the whole section is ignored")
    c = section(cfg, "commands")
    _check_rules(c, "commands", "extra_rules", warn)
    _check_str_list(c, "commands", "disable", warn, {r.id for r in commands.DEFAULT_RULES})
    _check_str_list(c, "commands", "protected_branches", warn)
    _check_str_list(c, "commands", "shell_tools", warn)
    if c.get("sql_tools") is not None and not (
            isinstance(c["sql_tools"], dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in c["sql_tools"].items())):
        warn("commands.sql_tools must map tool names to input field names (strings); ignored")
    w = section(cfg, "writes")
    _check_rules(w, "writes", "extra_block", warn)
    _check_rules(w, "writes", "extra_warn", warn)
    ids = ({r.id for r in writes.HARD_BLOCKS} | {r.id for r in writes.SOFT_WARNS}
           | {"claude-settings-hooks"})
    _check_str_list(w, "writes", "disable", warn, ids)
    scopes = w.get("agent_scopes")
    if scopes is not None and not isinstance(scopes, dict):
        warn("writes.agent_scopes must be an object of agent name to glob list; ignored")
    elif isinstance(scopes, dict):
        for agent, globs in scopes.items():
            if not (isinstance(globs, list) and globs
                    and all(isinstance(g, str) and g.strip() for g in globs)):
                warn(f"writes.agent_scopes['{agent}'] skipped: needs a non-empty list of glob strings")
    g = section(cfg, "gate_config")
    _check_str_list(g, "gate_config", "disable", warn, set(gateconfig.DEFAULT_PROTECTED), fold=True)
    if g.get("extra_protected") is not None and not isinstance(g["extra_protected"], dict):
        warn("gate_config.extra_protected must be an object of file name to reason; ignored")
    _check_str_list(section(cfg, "integrity"), "integrity", "extra_files", warn)
    p = section(cfg, "profiles")
    _check_str_list(p, "profiles", "always_on", warn)
    if p.get("tiers") is not None and not isinstance(p["tiers"], dict):
        warn("profiles.tiers must be an object of hook name to tier; ignored")


def section(cfg: dict, name: str) -> dict:
    sec = cfg.get(name)
    return sec if isinstance(sec, dict) else {}


def str_list(sec: dict, key: str) -> list:
    val = sec.get(key)
    if not isinstance(val, list):
        return []
    return [v for v in val if isinstance(v, str) and v.strip()]
