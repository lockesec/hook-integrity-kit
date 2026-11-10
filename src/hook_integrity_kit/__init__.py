"""hook-integrity-kit: integrity checking and guardrails for the Claude Code hook
surface.

Two halves:

* **Integrity.** A reviewed SHA-256 baseline of everything that runs automatically
  in a project (the ``hooks`` blocks of ``.claude/settings.json`` and
  ``settings.local.json``, every script they register, the modules those scripts
  import, and repo-local plugin ``hooks.json`` files). ``verify`` names any drift;
  the ``session-start`` hook reports it at the top of every session.
* **Guardrails.** PreToolUse hooks that refuse destructive shell commands, writes to
  sensitive paths (including the hooks block itself), and edits that weaken a
  lint or test gate.

Standard library only. Python 3.9+.
"""
from __future__ import annotations

__version__ = "0.1.1"

__all__ = ["__version__"]
