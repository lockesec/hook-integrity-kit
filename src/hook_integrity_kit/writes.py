"""``check-write``: refuse file writes to sensitive paths, and nudge on risky ones.

Registered as a PreToolUse hook on ``Write|Edit|MultiEdit|NotebookEdit``.

Three layers, evaluated in this order:

1. **Hard blocks** (deny, exit 2): credential and key files, system directories,
   git internals, the kit's own baseline and config, and any edit that changes
   the ``hooks`` block of a Claude Code settings file, an execution-affecting ``env``
   key, or a hook-control key (``disableAllHooks``, ``allowManagedHooksOnly``, ...).
2. **Per-agent write scopes** (deny): an agent listed in the config's
   ``agent_scopes`` may only write inside its allow-globs. Identity comes from the
   payload's ``agent_type``, which Claude Code sets inside a subagent and for a
   ``--agent`` session. Scopes are FAIL-CLOSED only for agents that have an
   entry. No identity, an unlisted agent, or an unusable config all fall back to
   the global rules: the kit never guesses identity and never blocks the main
   session on scope grounds.
3. **Nudges** (exit 0 plus ``additionalContext``): editing a hook script, and
   content that looks like a hard-coded secret.

Paths are judged TWICE: as written, and as resolved through symlinks (the file
the write would actually land in). An innocently named link to
``.claude/settings.json`` or to the baseline is judged as the file it points at,
and a link that cannot be resolved (a loop) is refused. The check runs before
the write, so a link swapped between the check and the write is out of reach:
this narrows the alias hole, it cannot close a race.

The settings rule is precise on purpose. Blocking every edit to
``settings.json`` would make permission changes impossible; allowing all of them
lets an agent register a new hook, which then runs automatically on every later
tool call. So the rule computes the hooks block, together with the ``env`` keys
that steer what an interpreter loads (``PATH``, ``PYTHONPATH``, ``BASH_ENV``,
``LD_PRELOAD``, ...), before and after the edit and blocks only when that
changes, the same line ``verify`` draws (an unrelated settings change is never
drift). An operator who really wants an agent to edit
hooks sets ``HOOK_KIT_ALLOW_HOOK_EDITS=1`` in the environment Claude Code runs
in; an agent's own Bash calls cannot set that for the hook process.
"""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from . import config as cfgmod
from . import hookio
from .manifest import exec_env, hook_controls, settings_surface_hash

WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
HOOK_EDIT_OVERRIDE = "HOOK_KIT_ALLOW_HOOK_EDITS"


@dataclass(frozen=True)
class PathRule:
    id: str
    pattern: str
    description: str


_TEMPLATE_ENV = r"(?!(?:example|sample|template|dist|defaults?)$)"

HARD_BLOCKS: Tuple[PathRule, ...] = (
    PathRule("env-file", r"(?:^|/)(?:[^/]*\.env|\.env\." + _TEMPLATE_ENV + r"[^/]+)$",
             ".env file (secrets); .env.example and similar templates are allowed"),
    PathRule("credentials-json", r"(?:^|/)credentials\.json$", "credentials file"),
    PathRule("aws-credentials", r"(?:^|/)\.aws/credentials$", "AWS credentials"),
    PathRule("ssh-dir", r"(?:^|/)\.ssh/", "SSH directory"),
    PathRule("ssh-private-key", r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$", "SSH private key"),
    PathRule("system-dir", r"^/(?:etc|bin|sbin|boot|usr/bin|usr/sbin|usr/lib|usr/local/bin|var/log)/",
             "system directory"),
    PathRule("git-internals", r"(?:^|/)\.git(?:/|$)",
             "git internals (.git/hooks and .git/config run code on later git commands; a "
             "`.git` FILE, as in a worktree or submodule, redirects git to another directory)"),
    PathRule("kit-baseline", r"(?:^|/)\.claude/hook-integrity\.json$",
             "the integrity baseline (only `hook-integrity-kit bless` writes it)"),
    PathRule("kit-config", r"(?:^|/)\.claude/hook-integrity-kit\.json$",
             "the guardrail config (an agent must not switch its own guardrails off)"),
    # Defence in depth: the registered hook command already ignores the working
    # directory. A package of the kit's own name anywhere but under a src/ directory
    # (this repository's layout) would be the first thing a `python -m` run imported.
    PathRule("kit-package-shadow", r"(?<!/src)(?<!^src)(?:^|/)hook_integrity_kit(?:\.py$|/)",
             "a module or package named like the kit (it would shadow the real one for "
             "anything that runs Python in the project directory)"),
)

SOFT_WARNS: Tuple[PathRule, ...] = (
    PathRule("hook-script", r"(?:^|/)\.claude/(?:hooks|plugins/[^/]+/hooks)/",
             "this is a hook script: it runs automatically. `hook-integrity-kit verify` "
             "will report it as MODIFIED until a human reviews it and runs `bless`"),
)

CONTENT_WARNINGS: Tuple[PathRule, ...] = (
    PathRule("hardcoded-password", r"password\s*=\s*[\"'][^\"']{4,}", "hard-coded password"),
    PathRule("hardcoded-api-key", r"api_key\s*=\s*[\"'][^\"']{8,}", "hard-coded API key"),
    PathRule("hardcoded-secret", r"secret\s*=\s*[\"'][^\"']{8,}", "hard-coded secret"),
    PathRule("aws-access-key", r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    PathRule("sk-token", r"sk-[a-zA-Z0-9]{20,}", "API key shaped like sk-..."),
)

SETTINGS_NAMES = ("settings.json", "settings.local.json")


def normalize(p: str) -> str:
    """Posix-normalize a path string (collapses ``..``; no filesystem access)."""
    return posixpath.normpath(str(p).replace("\\", "/"))


def target_path(ti: dict) -> str:
    fp = ti.get("file_path") or ti.get("notebook_path") or ""
    return fp if isinstance(fp, str) else ""


# ── the settings-hooks rule ─────────────────────────────────────────────────

def is_settings_file(fp: str) -> bool:
    """Case-insensitive: on a case-insensitive filesystem (the macOS and Windows
    defaults) ``.CLAUDE/Settings.json`` IS the settings file."""
    p = PurePosixPath(normalize(fp))
    return p.name.lower() in SETTINGS_NAMES and p.parent.name.lower() == ".claude"


class Unresolvable(Exception):
    """A path whose real target cannot be determined (a symlink loop)."""


def resolved_path(fp: str, cwd: Optional[str]) -> str:
    """The normalized real path a write to ``fp`` would land in. Raises
    Unresolvable for a symlink loop."""
    path = Path(fp)
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    try:
        # No `strict=` keyword: it is new in 3.10 (backported only to 3.9.23+),
        # and the default is already non-strict.
        return normalize(os.path.realpath(path))
    except (OSError, RuntimeError, ValueError) as e:     # loops raise on some versions
        raise Unresolvable(str(e)) from e


def _is_symlink_loop(fp: str, cwd: Optional[str]) -> bool:
    path = Path(fp)
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    if not path.is_symlink():
        return False
    try:
        path.resolve(strict=True)
        return False
    except FileNotFoundError:
        return False                                     # dangling: realpath still names the target
    except (OSError, RuntimeError):
        return True


PROTECTED_RELS = (".claude/settings.json", ".claude/settings.local.json",
                  ".claude/hook-integrity.json", ".claude/hook-integrity-kit.json",
                  ".git/config", ".env")


def _protected_files(cwd: Optional[str]) -> List[Path]:
    """The settings, baseline and config files this guard protects, found under the
    working directory and each of its parents, ``CLAUDE_PROJECT_DIR`` and the home
    directory (user-level settings)."""
    roots: List[Path] = []
    if cwd:
        roots += [Path(cwd), *Path(cwd).parents]
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        roots.append(Path(env))
    try:
        roots.append(Path.home())
    except (RuntimeError, KeyError):
        pass
    out: List[Path] = []
    for r in roots:
        for rel in PROTECTED_RELS:
            p = r / rel
            if p not in out:
                out.append(p)
    return out


def hard_link_to_protected(fp: str, cwd: Optional[str]) -> Optional[str]:
    """The protected file ``fp`` is a hard link to, or None. A file with more than one
    link is compared by (device, inode) against every protected settings, baseline and
    config file in reach: an innocent name for the same inode is the same file, and the
    path rules above would never see it. A symlink is judged by the path rules (it is
    resolved); this is the case a path cannot show. Hard links to a protected file kept
    outside the directories searched are out of reach."""
    cwd = cwd or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    path = Path(fp)
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    try:
        st = os.stat(path)
    except OSError:
        return None                                  # absent (a new file) or unreadable
    if not stat.S_ISREG(st.st_mode) or st.st_nlink < 2:
        return None
    me = os.path.realpath(path)
    for cand in _protected_files(cwd):
        if os.path.realpath(cand) == me:
            continue                 # the file itself is not "a link to itself"
        try:
            cs = os.stat(cand)
        except OSError:
            continue
        if (cs.st_dev, cs.st_ino) == (st.st_dev, st.st_ino):
            return str(cand)
    return None


def _surface_of(text: Optional[str]) -> Optional[Tuple[str, bool]]:
    """(hash of the hooks block plus execution-affecting env keys, whether
    either is non-empty) for a settings text, the same surface ``verify``
    pins. None if the text is not a JSON object."""
    if text is None:
        return settings_surface_hash({}, {}), False
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    hooks = data.get("hooks") or {}
    if not isinstance(hooks, dict):
        return None
    env = exec_env(data.get("env"))
    controls = hook_controls(data)
    return settings_surface_hash(hooks, env, controls), bool(hooks or env or controls)


def _apply_edit(text: str, old: str, new: str, replace_all: bool) -> Optional[str]:
    if not isinstance(old, str) or not isinstance(new, str) or old not in text:
        return None                     # the tool itself will reject this edit
    return text.replace(old, new) if replace_all else text.replace(old, new, 1)


def settings_hooks_change(tool: str, ti: dict, fp: str, cwd: Optional[str]) -> Optional[str]:
    """Why this write changes a settings hooks block, or None if it does not.

    Fails closed where the answer cannot be shown: new content that is not valid
    JSON, or a current file that cannot be parsed while the new one has hooks.
    """
    path = Path(fp)
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    try:
        current_text = path.read_text(encoding="utf-8") if path.is_file() else None
    except OSError:
        current_text = None
    before = _surface_of(current_text)

    if tool == "Write":
        new_text = ti.get("content")
        if not isinstance(new_text, str):
            return None
    elif tool in ("Edit", "MultiEdit"):
        edits = ti.get("edits") if tool == "MultiEdit" else [ti]
        # An absent file is empty text: Claude Code creates it from an edit whose
        # old_string is empty, so the edit is applied and judged like a Write.
        new_text = current_text if current_text is not None else ""
        for e in edits or []:
            if not isinstance(e, dict):
                return None
            new_text = _apply_edit(new_text, e.get("old_string"), e.get("new_string"),
                                   bool(e.get("replace_all")))
            if new_text is None:
                return None
    else:
        return None

    after = _surface_of(new_text)
    if after is None:
        return "the new content is not a JSON object, so it cannot be shown to leave hooks unchanged"
    if before is None:
        return ("the current file does not parse, and the new content registers hooks, "
                "sets an execution-affecting env key or sets a hook-control key" if after[1] else None)
    if before[0] != after[0]:
        return ("it changes the `hooks` block, an env key that steers what hooks load "
                "(PATH, PYTHON*, BASH_ENV, LD_*, ...), or a key that switches hooks off or "
                "narrows them (disableAllHooks, allowManagedHooksOnly, ...)")
    return None


# ── per-agent write scopes ──────────────────────────────────────────────────

def load_scopes(cfg: dict) -> Dict[str, List[str]]:
    """{agent_type: [glob, ...]} from the config. Malformed entries are skipped;
    well-formed siblings still enforce."""
    raw = cfgmod.section(cfg, "writes").get("agent_scopes")
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for agent, globs in raw.items():
        if (isinstance(agent, str) and isinstance(globs, list) and globs
                and all(isinstance(g, str) and g.strip() for g in globs)):
            out[agent] = [g.strip() for g in globs]
    return out


def _relative_candidates(file_path: str, cwd: str) -> List[str]:
    """Project-relative form(s) of file_path. Absolute paths are relativized
    against the payload cwd and CLAUDE_PROJECT_DIR (they differ in worktree
    sessions)."""
    norm = normalize(file_path)
    if not norm or norm == ".":
        return []
    path = PurePosixPath(norm)
    if not path.is_absolute():
        return [norm]
    out = []
    roots = [cwd, os.environ.get("CLAUDE_PROJECT_DIR", "")]
    # also the roots' real paths, so a target resolved through symlinks still
    # relativizes when the project itself sits behind a symlink
    roots += [os.path.realpath(r) for r in roots if r]
    for root in roots:
        if not root:
            continue
        try:
            rel = str(path.relative_to(PurePosixPath(normalize(root))))
        except ValueError:
            continue
        if rel not in out:
            out.append(rel)
    return out


def matches_glob(rel: str, pattern: str) -> bool:
    """``dir/**`` means the directory and everything under it; other patterns use
    fnmatch, where ``*`` crosses ``/`` (the allow-list is written by the project
    owner, not by an attacker)."""
    rel = rel.strip("/")
    pattern = pattern.strip().strip("/")
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        if any(ch in prefix for ch in "*?["):
            return fnmatch.fnmatch(rel, prefix) or fnmatch.fnmatch(rel, prefix + "/*")
        return rel == prefix or rel.startswith(prefix + "/")
    return fnmatch.fnmatch(rel, pattern)


def check_write_scope(payload: dict, scopes: Dict[str, List[str]]) -> Tuple[bool, str]:
    """(blocked, agent_type). Absolute patterns (leading ``/``) match the absolute
    path; relative patterns match the project-relative path. A path that escapes
    the project (``..``) matches no relative pattern."""
    agent = payload.get("agent_type") or ""
    if not agent:
        return False, ""
    patterns = scopes.get(agent)
    if not patterns:
        return False, agent
    file_path = target_path(hookio.tool_input(payload))
    if not file_path:
        return True, agent                  # scoped agent, unjudgeable target
    abs_norm = normalize(file_path)
    for pattern in patterns:
        if pattern.startswith("/") and matches_glob(abs_norm, pattern):
            return False, agent
    for rel in _relative_candidates(file_path, payload.get("cwd") or ""):
        if rel.startswith(".."):
            continue
        for pattern in patterns:
            if not pattern.startswith("/") and matches_glob(rel, pattern):
                return False, agent
    return True, agent


# ── rule assembly and the hook entry ─────────────────────────────────────────

def _extra(sec: dict, key: str, warnings: List[str]) -> List[PathRule]:
    out = []
    for i, raw in enumerate(sec.get(key) or []):
        if not isinstance(raw, dict) or not isinstance(raw.get("pattern"), str):
            warnings.append(f"writes.{key}[{i}] skipped: needs a 'pattern' string")
            continue
        try:
            re.compile(raw["pattern"])
        except re.error as e:
            warnings.append(f"writes.{key}[{i}] skipped: bad regex ({e})")
            continue
        out.append(PathRule(str(raw.get("id") or f"{key}-{i}"), raw["pattern"],
                            str(raw.get("description") or raw["pattern"])))
    return out


def active_rules(cfg: dict) -> Tuple[List[PathRule], List[PathRule], bool, List[str]]:
    """(hard blocks, soft warns, settings-hooks rule on?, warnings)."""
    sec = cfgmod.section(cfg, "writes")
    disabled = set(cfgmod.str_list(sec, "disable"))
    warnings: List[str] = []
    hard = [r for r in HARD_BLOCKS if r.id not in disabled] + _extra(sec, "extra_block", warnings)
    soft = [r for r in SOFT_WARNS if r.id not in disabled] + _extra(sec, "extra_warn", warnings)
    return hard, soft, "claude-settings-hooks" not in disabled, warnings


def decide(payload: dict, cfg: dict) -> Tuple[str, str]:
    """('deny' | 'nudge' | 'allow', message). Pure: no printing."""
    tool = payload.get("tool_name")
    if tool not in WRITE_TOOLS:
        return "allow", ""
    ti = hookio.tool_input(payload)
    fp = target_path(ti)
    if not fp:
        return "allow", ""
    norm = normalize(fp)
    cwd = payload.get("cwd")
    hard, soft, settings_rule, _ = active_rules(cfg)

    if _is_symlink_loop(fp, cwd):
        return "deny", (f"BLOCKED: {fp} is a symlink that does not resolve (a loop), so "
                        "the file this write would reach cannot be checked.")
    real = resolved_path(fp, cwd)
    forms = [norm] + ([real] if real != norm else [])
    via = "" if real == norm else f" (resolves to {real})"

    linked = hard_link_to_protected(fp, cwd)
    if linked:
        return "deny", (f"BLOCKED: {fp} is a hard link to {linked}, which this guard protects "
                        "(a hard link is the same file under another name, so this write "
                        "would change it). Write a different file, or ask the user to make "
                        "this change.")

    for r in hard:
        if any(re.search(r.pattern, f, re.IGNORECASE) for f in forms):
            return "deny", (f"BLOCKED: write to {r.description} (rule {r.id}) - {fp}{via}. "
                            "Use a different location, or ask the user to make this change.")

    if settings_rule and any(is_settings_file(f) for f in forms):
        why = settings_hooks_change(tool, ti, real, cwd)
        if why and os.environ.get(HOOK_EDIT_OVERRIDE) != "1":
            return "deny", (f"BLOCKED: this edit to {fp}{via} is refused because {why} "
                            "(rule claude-settings-hooks). Hooks run automatically on later "
                            "tool calls and sessions, so a person should make this change "
                            "and then run `hook-integrity-kit bless`. Other settings "
                            "(permissions, model, other env keys) can be edited normally.")

    scopes = load_scopes(cfg)
    if scopes and not (payload.get("agent_id") and not payload.get("agent_type")):
        blocked, agent = check_write_scope(payload, scopes)
        if not blocked and real != norm:
            # a link inside the scope that points outside it is outside it
            aliased = dict(payload, tool_input=dict(ti, file_path=real))
            blocked, agent = check_write_scope(aliased, scopes)
        if blocked:
            return "deny", (f"BLOCKED: write-scope violation - agent '{agent}' may not write "
                            f"{fp}. Declared scope: {', '.join(scopes.get(agent, []))}. "
                            "Write inside the declared scope instead.")

    notes = [f"CAUTION: {r.description} - {fp}{via}" for r in soft
             if any(re.search(r.pattern, f, re.IGNORECASE) for f in forms)]
    content = ti.get("content") or ti.get("new_string") or ti.get("new_source") or ""
    if isinstance(content, str) and content:
        notes += [f"SECRET WARNING: {r.description} in the content being written"
                  for r in CONTENT_WARNINGS if re.search(r.pattern, content, re.IGNORECASE)]
    if notes:
        return "nudge", "\n".join(notes)
    return "allow", ""


def run(payload: Optional[dict], oversized: bool, cfg: dict) -> int:
    if oversized:
        return hookio.deny(f"BLOCKED: {hookio.refusal_reason(oversized)}, so the "
                           "write target could not be examined.")
    if payload is None:
        return hookio.EXIT_ALLOW
    if payload.get("agent_id") and not payload.get("agent_type") and load_scopes(cfg):
        print("hook-integrity-kit: subagent identity unknown (agent_id without "
              "agent_type); write scopes fall back to the global rules", file=sys.stderr)
    verdict, msg = decide(payload, cfg)
    if verdict == "deny":
        return hookio.deny(msg)
    if verdict == "nudge":
        return hookio.nudge(msg)
    return hookio.EXIT_ALLOW
