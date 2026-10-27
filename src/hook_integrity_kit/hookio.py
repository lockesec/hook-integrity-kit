"""The Claude Code hook protocol, in one place.

Contract as documented in the Claude Code hooks reference
(https://code.claude.com/docs/en/hooks, sections "Exit code output",
"JSON output" and "PreToolUse decision control"), checked 2026-09-24:

* The hook receives one JSON object on stdin (``tool_name``, ``tool_input``,
  ``cwd``, ``hook_event_name``, and ``agent_id`` / ``agent_type`` inside a
  subagent).
* **Blocking.** On PreToolUse, exit code 2 blocks the tool call "whether or not
  you print JSON", and stderr becomes the reason when no JSON reason is given.
  The structured form is ``hookSpecificOutput.permissionDecision = "deny"`` with
  ``permissionDecisionReason``. The older top-level ``"decision": "block"`` form
  is deprecated. A deny here does both: the structured JSON on stdout, the same
  reason on stderr, and exit 2. Either channel alone is enough to block; the
  pair means the reason reaches the model even if one channel is dropped.
* **Nudging.** Advice that must NOT stop the call exits 0 and puts the text in
  ``hookSpecificOutput.additionalContext``. Plain stdout on a PreToolUse exit 0
  goes to the debug log only, so a bare ``print`` reaches nobody. Exit 2 is never
  used for advice: it blocks the call, and inside a subagent a blocked call ends
  that line of work.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Optional, TextIO, Tuple

#: A payload larger than this that also fails to parse is refused (see read_payload).
MAX_PAYLOAD = 1024 * 1024
#: Hard ceiling on what is read at all. A payload over it is refused unparsed:
#: memory use stays bounded, and a call too large to examine is not waved through.
MAX_INPUT = 32 * 1024 * 1024

EXIT_ALLOW = 0
EXIT_DENY = 2

#: Why a payload was refused unparsed. Both values are truthy, so a caller that
#: only asks "was it refused?" keeps working; the guards use the value to say why.
REFUSED_OVERSIZED = "oversized"
REFUSED_NOT_UTF8 = "not-utf8"
REFUSED_TOO_DEEP = "too-deep"


def refusal_reason(refused: object) -> str:
    """The sentence a guard puts in its refusal for a payload it could not read."""
    if refused == REFUSED_NOT_UTF8:
        return "the hook payload is not valid UTF-8"
    if refused == REFUSED_TOO_DEEP:
        return "the hook payload is nested too deeply to parse"
    return "the hook payload is over 1 MiB and could not be parsed"


def _read_bytes(stream: Any) -> bytes:
    """Up to ``MAX_INPUT + 1`` raw bytes. Bytes, never text: a text stream decodes
    with the process locale (``surrogateescape`` under the C locale), so the same
    payload would be judged differently depending on the environment."""
    if stream is None:
        stream = sys.stdin
    if stream is None:
        # Closed stdin (`<&-`): there is no payload to judge. Raised, not
        # swallowed, so the guard turns it into a refusal.
        raise OSError("standard input is closed")
    raw = getattr(stream, "buffer", None)
    if raw is not None:
        data = raw.read(MAX_INPUT + 1)
    else:                                   # an in-memory text stream (tests, embedding)
        data = stream.read(MAX_INPUT + 1)
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    return data


def read_payload(stream: Optional[Any] = None) -> Tuple[Optional[dict], Any]:
    """Read and parse the hook's stdin.

    Returns ``(payload, refused)``: ``refused`` is False, or a truthy reason
    (``REFUSED_OVERSIZED`` / ``REFUSED_NOT_UTF8`` / ``REFUSED_TOO_DEEP``).

    * A small payload that is not a JSON object returns ``(None, False)``: the
      guard lets the call through, because there is no file path or command in
      it to judge.
    * A payload that is not valid UTF-8 returns ``(None, REFUSED_NOT_UTF8)``:
      refused. The bytes are decoded strictly here, so this holds under every
      locale.
    * A payload nested deeper than the JSON parser can follow returns
      ``(None, REFUSED_TOO_DEEP)``: refused.
    * A payload over ``MAX_PAYLOAD`` bytes that does not parse returns
      ``(None, REFUSED_OVERSIZED)`` and the guard refuses. A giant tool call is the one
      malformed shape an agent can manufacture on purpose, and a guard that a
      large enough input switches off is not a guard.

    A large but well-formed payload (a big Write) parses normally and is judged
    on its content, up to ``MAX_INPUT``. Beyond that the stream is not read
    further and the call is refused as oversized: reading it all would make the
    guard's memory use attacker-controlled.

    Anything else that goes wrong while reading (a closed stdin, an I/O error)
    is raised; ``cli._guard`` turns that into a refusal.
    """
    data = _read_bytes(stream)
    if len(data) > MAX_INPUT:
        return None, REFUSED_OVERSIZED
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError:
        # Bytes that are not UTF-8 cannot be judged: fail closed.
        return None, REFUSED_NOT_UTF8
    try:
        parsed = json.loads(raw) if raw.strip() else None
    except RecursionError:
        return None, REFUSED_TOO_DEEP
    except (json.JSONDecodeError, ValueError):
        return None, REFUSED_OVERSIZED if len(data) > MAX_PAYLOAD else False
    if not isinstance(parsed, dict):
        return None, False
    return parsed, False


def deny(reason: str, event: str = "PreToolUse",
         out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    """Block the tool call: structured deny on stdout, reason on stderr, exit 2."""
    out = out or sys.stdout
    err = err or sys.stderr
    out.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": event,
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}) + "\n")
    err.write(reason + "\n")
    return EXIT_DENY


def nudge(context: str, event: str = "PreToolUse",
          out: Optional[TextIO] = None) -> int:
    """Let the call proceed and give the model a note. Always exit 0."""
    out = out or sys.stdout
    out.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": event,
        "additionalContext": context,
    }}) + "\n")
    return EXIT_ALLOW


def tool_input(payload: dict) -> dict:
    ti: Any = payload.get("tool_input")
    return ti if isinstance(ti, dict) else {}
