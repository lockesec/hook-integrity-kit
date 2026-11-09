"""Hook profiles: run fewer hooks for quick work, more for careful work.

The profile/disable vocabulary (``minimal`` / ``standard`` / ``strict``, plus a
comma-separated list of disabled hooks) follows everything-claude-code's
``scripts/lib/hook-flags.js`` (ECC, https://github.com/affaan-m/ECC, MIT).
The tier table, the always-on set, and the "is this disable actually enforceable"
report are ours.

Any hook of yours can consult it::

    from hook_integrity_kit.profile import should_run
    if not should_run("my_slow_linter"):
        sys.exit(0)

Environment (read from the hook's own process, so the operator sets it, not the
agent):

* ``HOOK_PROFILE=minimal|standard|strict`` (default ``standard``; anything else
  reads as ``standard``);
* ``DISABLED_HOOKS=a,b,c`` disables named hooks in every profile.

Tiers: ``critical`` runs in every profile, ``standard`` in standard and strict,
``strict`` only in strict. An unknown hook defaults to ``standard``. The kit's
own guards are ALWAYS ON: the profile never switches a safety gate off. An
explicit ``DISABLED_HOOKS`` entry still wins, because that is a deliberate
operator act.

A hook is only profile-gated IF IT ASKS. Nothing here can stop a hook that
Claude Code launches directly and that never calls ``should_run``, so a name in
``DISABLED_HOOKS`` is a request that hook may never read.
``unenforceable_disables`` names those cases instead of letting a status line
claim "Disabled: x" while x keeps running.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set

from . import config as cfgmod

PROFILE_ORDER = {"minimal": 0, "standard": 1, "strict": 2}
TIER_LEVEL = {"critical": 0, "standard": 1, "strict": 2}

KIT_GUARDS: FrozenSet[str] = frozenset(
    {"check-command", "check-write", "check-gate-config", "session-start"})

_SHOULD_RUN_CALL = re.compile(r"\bshould_run\s*\(")
_HOOK_SCRIPT_REF = re.compile(r"/\.claude/hooks/([A-Za-z0-9_]+)\.py")


def get_profile() -> str:
    p = os.environ.get("HOOK_PROFILE", "standard").lower().strip()
    return p if p in PROFILE_ORDER else "standard"


def get_disabled() -> Set[str]:
    raw = os.environ.get("DISABLED_HOOKS", "").strip()
    return {h.strip() for h in raw.split(",") if h.strip()} if raw else set()


def tiers_from(cfg: Optional[dict]) -> Dict[str, str]:
    raw = cfgmod.section(cfg or {}, "profiles").get("tiers")
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and v in TIER_LEVEL}


def always_on_from(cfg: Optional[dict]) -> FrozenSet[str]:
    return KIT_GUARDS | frozenset(cfgmod.str_list(cfgmod.section(cfg or {}, "profiles"),
                                                  "always_on"))


def should_run(hook_name: str, cfg: Optional[dict] = None) -> bool:
    if hook_name in get_disabled():
        return False
    if hook_name in always_on_from(cfg):
        return True
    tier = tiers_from(cfg).get(hook_name, "standard")
    return TIER_LEVEL[tier] <= PROFILE_ORDER[get_profile()]


def consults_gate(hooks_dir: Path, hook_name: str) -> Optional[bool]:
    """Does this hook's own file call ``should_run(``? None if unreadable: never
    True, because assuming a gate exists is the failure this reports on."""
    try:
        src = (hooks_dir / f"{hook_name}.py").read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return None
    return bool(_SHOULD_RUN_CALL.search(src))


def registered_hook_names(root: Path) -> Set[str]:
    """Stems of .claude/hooks/*.py that settings files launch directly. Empty on
    any read failure: an unreadable file must not produce claims about hooks."""
    names: Set[str] = set()
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        try:
            names |= set(_HOOK_SCRIPT_REF.findall((root / rel).read_text(encoding="utf-8")))
        except OSError:
            continue
    return names


def unenforceable_disables(root: Path, disabled: Optional[Set[str]] = None) -> List[str]:
    """Disabled names that CANNOT take effect: registered directly and never
    calling should_run. A hook launched by another hook may be gated by its
    caller, so only registered-and-ungated hooks are reported."""
    disabled = get_disabled() if disabled is None else disabled
    registered = registered_hook_names(root)
    hooks_dir = root / ".claude" / "hooks"
    return [h for h in sorted(disabled)
            if h in registered and consults_gate(hooks_dir, h) is False]


def profile_info(root: Optional[Path] = None, cfg: Optional[dict] = None) -> str:
    profile = get_profile()
    disabled = get_disabled()
    tiers = tiers_from(cfg)
    always = always_on_from(cfg)
    always_active = sum(1 for h in always if h not in disabled)
    gated_active = sum(1 for h, t in tiers.items()
                       if h not in always and h not in disabled
                       and TIER_LEVEL[t] <= PROFILE_ORDER[profile])
    info = (f"Hook profile: {profile} ({always_active} always-on + {gated_active} "
            f"gated-active / {len(tiers)} tiered)")
    if disabled:
        info += f" | Disabled: {', '.join(sorted(disabled))}"
        stuck = unenforceable_disables(root, disabled) if root else []
        if stuck:
            info += (f" | NOT ACTUALLY DISABLED ({len(stuck)}): {', '.join(stuck)} - "
                     "registered directly and never call should_run(), so the setting "
                     "cannot reach them; they are RUNNING")
    return info
