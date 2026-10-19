# Install: the snippet, `onFailure: block`, and recovery

Moved here verbatim from the README's former "Install" section; the README keeps the
short form.

`install` never writes your settings; stdout is the snippet as pure JSON, the
instructions go to stderr. Blessing is your act after review: `check-command` refuses
an agent's `bless` by text match, an accident guard, not a boundary against a
determined agent ([THREAT_MODEL.md](../THREAT_MODEL.md)). The snippet sets
`"onFailure": "block"` on each guard (Claude Code 2.1.295+), so a guard that times out
or crashes refuses the call.

**The snippet is machine-specific.** It holds the absolute path of the Python that ran
`install` (override with `--python PATH`); run it where the project is used. Each hook
runs `PYTHON -c '<program>'`, not `PYTHON -m hook_integrity_kit`: the program removes
every non-absolute `sys.path` entry before it imports the kit, so a
`hook_integrity_kit/` package or a `json.py` inside the project cannot replace the
guards (a `PYTHONPATH` that names the project still can; [THREAT_MODEL.md](../THREAT_MODEL.md)). Because
of `"onFailure": "block"`, a missing interpreter or uninstalled package makes **every
guarded call (Bash, Write, Edit) refuse**. Recovery has to happen
**outside Claude Code**: with `onFailure: block` the Bash, Write and Edit tools are
all refused, and the kit's own settings-hooks rule refuses edits to the `hooks`
block, so Claude cannot fix it. In a terminal or an editor, remove or correct the
three `PreToolUse` entries in `.claude/settings.json` (or re-run `install --python
PATH` and paste the result), then restart the session. Options
(`--root`, `--baseline`, `--json`, `--python`): [rules.md](rules.md#command-line-options).

A bare interpreter name that is on `PATH` is accepted by `--python` (`install --python
python3` writes `python3` into the snippet, resolved on `PATH` when the hook runs); a
name that is not on `PATH`, an empty value or a path that is not an executable file is
refused (exit 64).
