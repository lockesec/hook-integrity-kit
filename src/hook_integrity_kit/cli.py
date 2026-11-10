"""Command line: ``hook-integrity-kit``.

    hook-integrity-kit bless    [--root R] [--baseline P] [--include-global]
    hook-integrity-kit verify   [--root R] [--baseline P] [--json]
    hook-integrity-kit session-start          # a SessionStart hook
    hook-integrity-kit check-command          # a PreToolUse hook (Bash)
    hook-integrity-kit check-write            # a PreToolUse hook (Write|Edit|...)
    hook-integrity-kit check-gate-config      # a PreToolUse hook (Write|Edit|MultiEdit)
    hook-integrity-kit install                # print the settings.json snippet
    hook-integrity-kit rules                  # list the active guard rules
    hook-integrity-kit profile                # show the hook profile

Exit codes for ``verify``:

    0   the hook surface matches the baseline
    1   DRIFT: something that runs automatically changed (each change is named)
    2   NOT EVALUABLE: no baseline; an unreadable baseline, settings file,
        plugin registration or hooked file; a hooked Python file this
        interpreter cannot parse; or no project root. Never a pass.
    64  usage error

``bless`` exits 0 on success and 2 when it cannot read the surface. The
``check-*`` hooks exit 0 to allow (optionally with a note for the model) and 2
to block. ``session-start`` always exits 0: it warns, it never blocks a session.
Global (~/.claude) drift is reported by name and never changes an exit code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, commands, events, gateconfig, hookio, manifest, profile, writes
from . import config as cfgmod

EXIT_OK, EXIT_DRIFT, EXIT_NOT_EVALUABLE, EXIT_USAGE = 0, 1, 2, 64
PROG = "hook-integrity-kit"


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Review and pin the hooks a Claude Code project runs, then get told "
                    "file by file when anything changes. Also guards an agent's riskiest "
                    "shell commands and file writes. Standard library only.",
        epilog="verify exits 0 = matches, 1 = drift, 2 = could not look. The check-* guards "
               "use 2 differently: exit 2 means BLOCK this tool call.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    def surface_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", type=Path, default=None,
                       help="project root (default: nearest ancestor with .claude/ or .git)")
        p.add_argument("--baseline", type=Path, default=None,
                       help=f"baseline file (default: <root>/{manifest.BASELINE_REL.as_posix()})")
        p.add_argument("--settings", type=Path, action="append", default=None,
                       help="settings file(s) to read (default: .claude/settings.json and "
                            ".claude/settings.local.json)")
        p.add_argument("--global-dir", type=Path, default=None,
                       help="user-level Claude dir for global coverage (default: ~/.claude)")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("bless", help="record a SHA-256 baseline of the hooks you have reviewed")
    surface_args(p)
    p.add_argument("--allow-missing", action="store_true",
                   help="bless even when a registered script does not exist (it is recorded "
                        "as MISSING and `verify` keeps reporting it)")
    p.add_argument("--diff", action="store_true",
                   help="after writing the new baseline, print the git diff of each modified "
                        "file since the commit that last wrote the baseline")
    p.add_argument("--include-global", action="store_true",
                   help="also hash the ~/.claude hook surface (warn-only); this writes "
                        "home-directory paths into the baseline")
    p = sub.add_parser("verify", help="compare the hooks with the baseline and name each change (exit 1 on drift)")
    surface_args(p)
    p.add_argument("--format", choices=("text", "json", "jsonl"), default=None,
                   help="jsonl: one event per finding plus a RUN event (docs/events.md)")
    p = sub.add_parser("session-start", help="run verify at session start and warn the model; never blocks")
    surface_args(p)
    p.add_argument("--events", type=Path, default=None, metavar="FILE",
                   help="also append the run's events (JSONL, docs/events.md) to FILE for a log "
                        "shipper; a write error goes to stderr and never stops the session")
    for name, helptext in (("check-command", "guard for Bash: refuses risky shell commands (exit 2 = block)"),
                           ("check-write", "guard for file writes: refuses protected files and hook edits (exit 2 = block)"),
                           ("check-gate-config", "guard for edits that weaken a linter or test config (exit 2 = block)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--config", type=Path, default=None,
                       help=f"config file (default: <project>/{cfgmod.CONFIG_REL.as_posix()})")
    p = sub.add_parser("install", help="print the hooks block to paste into .claude/settings.json (writes nothing)")
    p.add_argument("--python", default=None,
                   help="interpreter to run the kit with (default: this one)")
    p.add_argument("--shell-tool", action="append", default=[], metavar="NAME",
                   help="also register check-command for this tool name (repeatable); the "
                        "tool's input must carry the shell text in `command`, which this kit "
                        "has not verified for any tool but Bash")
    p = sub.add_parser("audit", help="list what a checkout runs on its own, with no baseline (reads only)")
    p.add_argument("--root", type=Path, default=None,
                   help="project root (default: the current directory)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--format", choices=("text", "json", "jsonl"), default=None,
                   help="jsonl: one event per auto-run item plus a RUN event (docs/events.md)")
    p.add_argument("--strict", action="store_true",
                   help="exit 1 when ANY item runs on its own, not only when something is "
                        "flagged (for CI, or a gate before opening a checkout)")
    p = sub.add_parser("rules", help="list the active guard rules and their severity")
    p.add_argument("--config", type=Path, default=None, help="config file to read rules from")
    p.add_argument("--root", type=Path, default=None, help="project root")
    p = sub.add_parser("profile", help="show the active hook profile and any disabled hooks")
    p.add_argument("--root", type=Path, default=None, help="project root")
    return ap


def _root(arg: Optional[Path], hook: bool = False) -> Path:
    chosen = arg
    if chosen is None and hook and os.environ.get("CLAUDE_PROJECT_DIR"):
        chosen = Path(os.environ["CLAUDE_PROJECT_DIR"])
    if chosen is not None:
        if not chosen.is_dir():
            raise manifest.NotEvaluable(f"the project root {chosen} does not exist "
                                        "or is not a directory")
        return chosen.resolve()
    return manifest.find_project_root()


def _global_dir(arg: Optional[Path]) -> Optional[Path]:
    if arg is not None:
        return arg
    env = os.environ.get("HOOK_INTEGRITY_GLOBAL_DIR")
    return Path(env) if env else None


def _extra_globs(root: Path) -> List[str]:
    cfg = cfgmod.load(project=root)
    return cfgmod.str_list(cfgmod.section(cfg, "integrity"), "extra_files")


def _write_atomic(path: Path, text: str) -> None:
    """Replace ``path`` in one step, so an interrupted bless never leaves a
    half-written baseline (which would read as NOT EVALUABLE, or worse)."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _bless_failed(why: str) -> int:
    print(f"{PROG}: bless failed: {why}", file=sys.stderr)
    return EXIT_NOT_EVALUABLE


def cmd_bless(a: argparse.Namespace) -> int:
    try:
        root = _root(a.root)
        baseline_path = a.baseline or root / manifest.BASELINE_REL
        if baseline_path.is_dir():
            print(f"{PROG}: bless refused: the baseline path {baseline_path} is a directory; "
                  "point --baseline at a file", file=sys.stderr)
            return EXIT_NOT_EVALUABLE
        previous = None
        if baseline_path.is_file():
            previous = manifest.check(root, baseline_path, a.settings, _global_dir(a.global_dir))
        surface_notes: List[str] = []
        base = manifest.build_baseline(root, a.settings, _extra_globs(root),
                                       a.include_global, _global_dir(a.global_dir),
                                       surface_notes)
    except manifest.NotEvaluable as e:
        return _bless_failed(str(e))
    except OSError as e:
        return _bless_failed(f"cannot read {e.filename or 'the surface'}: {e.strerror or e}")
    if previous is not None and previous.get("status") == "error":
        print(f"{PROG}: the previous baseline could not be used and is being replaced, so nothing "
              f"was compared with it: {previous.get('error')}", file=sys.stderr)
    missing = [f["path"] for f in base["files"] if f["sha256"] is None]
    if missing and not a.allow_missing:
        print(f"{PROG}: bless refused: {len(missing)} registered file(s) are MISSING on disk:",
              file=sys.stderr)
        for m in missing:
            print(f"  MISSING  {m}", file=sys.stderr)
        print("A missing hook script is a finding, not a baseline. Create it, fix or remove "
              "the registration, or pass --allow-missing to record the gap anyway (`verify` "
              "keeps reporting it until the file exists and is blessed).", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    if baseline_path.is_symlink():
        # Writing through a link would put the baseline wherever the link points
        # (possibly outside the project) and hash-check against that later.
        print(f"{PROG}: bless refused: {baseline_path} is a symlink; point --baseline at a "
              "regular file", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    try:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        _write_atomic(baseline_path, json.dumps(base, indent=2) + "\n")
    except OSError as e:
        return _bless_failed(f"cannot write {baseline_path}: {e.strerror or e}")
    if a.json:
        print(json.dumps(base, indent=2))
        return EXIT_OK
    if previous and previous["status"] == "drift":
        print("Changes since the previous baseline (now blessed):")
        print(manifest.render_report(previous))
        print()
        if getattr(a, "diff", False):
            for rel in previous.get("modified", []):
                print(f"--- what changed in {rel}:")
                print(manifest.diff_since_baseline(root, baseline_path, rel))
            print()
    print(f"Blessed {len(base['files'])} file(s) into {baseline_path}:")
    for f in base["files"]:
        h = (f["sha256"] or "MISSING")[:12]
        print(f"  {h}  {f['path']}  [{', '.join(f['events'])}]")
    for label in sorted(base["settings_hooks_sha256"]):
        present = (root / label).is_file() or Path(label).is_file()
        print(f"  hooks block pinned: {label}"
              + ("" if present else " (absent now; hooks added there later are drift)"))
    if base["bytecode"]:
        print(f"  {len(base['bytecode'])} bytecode cache(s) beside imported modules pinned "
              "(a cache for this Python is also checked against its source on every verify)")
    for e in base["external_unchecked"]:
        print(f"  NOT CHECKED (outside the project): [{e['event']}] {e['path']}")
    if base["unregistered_on_disk"]:
        print(f"  {len(base['unregistered_on_disk'])} unregistered hook file(s) on disk "
              "(informational, not hashed)")
    # The same NOT CHECKED lines `verify` prints: handler types other than command,
    # npx-style commands, statusLine and the other command settings, .mcp.json,
    # imports that resolve outside the project, shell `source`, frontmatter hooks.
    for n in surface_notes:
        print(f"  NOT CHECKED: {n}")
    for n in manifest.out_of_scope_notes(_global_dir(a.global_dir), bool(base["global"].get("covered"))):
        print(f"  NOT CHECKED: {n}")
    g = base["global"]
    if g.get("covered"):
        print(f"  global ~/.claude: {len(g['registrations'])} registration(s), "
              f"{len(g['files'])} script(s) hashed (warn-only)")
        if g.get("unresolved_registrations"):
            print(f"  NOT CHECKED: {g['unresolved_registrations']} user-level hook "
                  "registration(s) resolve to no readable script (an npx-style or "
                  "missing command): a change to what they run is invisible to this baseline")
    print("Blessing says you reviewed every file above. Commit the baseline with the hook change.")
    return EXIT_OK


def _run_check(a: argparse.Namespace, hook: bool) -> dict:
    try:
        root = _root(a.root, hook=hook)
    except manifest.NotEvaluable as e:
        return {"status": "error", "error": str(e)}
    try:
        return manifest.check(root, a.baseline, a.settings, _global_dir(a.global_dir))
    except manifest.NotEvaluable as e:
        return {"status": "error", "error": str(e)}
    except (OSError, ValueError, KeyError, TypeError, RecursionError, MemoryError) as e:
        # Never a traceback with exit 1 (1 means DRIFT): the check could not look.
        what = e.strerror if isinstance(e, OSError) and e.strerror else str(e)
        return {"status": "error",
                "error": f"the check could not complete ({e.__class__.__name__}: {what})"}


def _project(a: argparse.Namespace, hook: bool) -> Optional[str]:
    """The project root for an event's `project` field, or None when it cannot be found."""
    try:
        return str(_root(a.root, hook=hook))
    except manifest.NotEvaluable:
        return None


def cmd_verify(a: argparse.Namespace) -> int:
    findings = _run_check(a, hook=False)
    fmt = a.format or ("json" if a.json else "text")
    if fmt == "jsonl":
        print(events.dumps(events.from_verify(findings, _project(a, hook=False))))
    else:
        print(json.dumps(findings, indent=2) if fmt == "json" else manifest.render_report(findings))
    if findings["status"] == "clean":
        return EXIT_OK
    if findings["status"] == "drift":
        return EXIT_DRIFT
    return EXIT_NOT_EVALUABLE


class _Deadline(Exception):
    """The session-start check used up its own time budget."""


#: Seconds the session-start check may run. The installed hook's timeout is 30, so the
#: check says "did not finish" itself, before Claude Code kills it and nothing is shown.
SESSION_DEADLINE_SECONDS = 20.0


def _arm_deadline() -> None:
    try:
        import signal
        limit = float(os.environ.get("HOOK_INTEGRITY_SESSION_DEADLINE", SESSION_DEADLINE_SECONDS))

        def fire(_sig, _frame):
            raise _Deadline()
        signal.signal(signal.SIGALRM, fire)
        signal.setitimer(signal.ITIMER_REAL, max(limit, 0.001))
    except (AttributeError, ValueError, OSError):
        pass                      # no SIGALRM (Windows) or not the main thread: no deadline


def _disarm_deadline() -> None:
    try:
        import signal
        signal.setitimer(signal.ITIMER_REAL, 0)
    except (AttributeError, ValueError, OSError):
        pass


def cmd_session_start(a: argparse.Namespace) -> int:
    """SessionStart contract: stdout is added to the session context (the model
    sees it); stderr is a short banner for the human; exit 0 always. It warns and
    continues: a hook in the repository cannot be an unbypassable gate, and a hard
    block would stop every session after each legitimate hook edit."""
    t0 = time.monotonic()
    try:
        try:
            sys.stdin.read()
        except (OSError, ValueError):
            pass
        if not profile.should_run("session-start"):
            return EXIT_OK
        _arm_deadline()
        try:
            findings = _run_check(a, hook=True)
        finally:
            _disarm_deadline()
        if a.events is not None:
            try:
                events.append(a.events, events.from_verify(findings, _project(a, hook=True),
                                                           source="session-start"))
            except OSError as e:
                print(f"hook-integrity: events not written to {a.events} ({e.strerror or e})",
                      file=sys.stderr)
        status = findings["status"]
        gstatus = findings.get("global_status")
        if status == "clean":
            # Clean is the REPO surface only. Global drift is kept out of `status`
            # by design, so it must be printed here or nobody ever sees it.
            if (findings.get("info_new_unregistered") or findings.get("external_unchecked")
                    or gstatus in ("drift", "not-covered")):
                print(manifest.render_report(findings))
            if gstatus == "drift":
                print("hook-integrity: GLOBAL hook surface changed (warn-only); see the "
                      "session context", file=sys.stderr)
            return EXIT_OK
        if status in ("no-baseline", "error"):
            report = manifest.render_report(findings)
            print(report)
            print(report, file=sys.stderr)
            return EXIT_OK
        ms = int((time.monotonic() - t0) * 1000)
        print("=" * 70)
        print("HOOK INTEGRITY WARNING - the auto-executing hook surface changed")
        print("=" * 70)
        print(manifest.render_report(findings))
        print(f"(checked in {ms} ms; the session continues: warn-and-continue by design)")
        print("hook-integrity: DRIFT - see the session context; after review, re-bless "
              "with: hook-integrity-kit bless", file=sys.stderr)
        return EXIT_OK
    except _Deadline:
        _disarm_deadline()
        print("hook-integrity: NOT EVALUABLE - the check did not finish within its time budget "
              "(a hook file or an import may be very large or slow to read). Run "
              "`hook-integrity-kit verify` and inspect the hook files before trusting this session.")
        return EXIT_OK
    except Exception as e:  # noqa: BLE001 - this hook must never break a session
        _disarm_deadline()
        print(f"hook-integrity: check skipped ({e.__class__.__name__}: {e})")
        return EXIT_OK


#: The tools each guard judges. An internal error on one of THESE is a call the
#: guard was supposed to examine and could not, so it is refused.
_GUARDED_TOOLS = {
    "check-command": ("Bash",),
    "check-write": ("Write", "Edit", "MultiEdit", "NotebookEdit"),
    "check-gate-config": ("Write", "Edit", "MultiEdit"),
}


def _guard(a: argparse.Namespace, name: str, fn) -> int:
    """Run one guard. Every way this can go wrong ends in a refusal: a guard
    that crashes must not become a bypass (Claude Code treats exit 1 as
    non-blocking), so nothing here, the reader included, can escape as an
    uncaught exception."""
    payload: Optional[dict] = None
    oversized: object = False
    read_error: Optional[str] = None
    cfg: Optional[dict] = None
    try:
        payload, oversized = hookio.read_payload()
    except BaseException as e:  # noqa: BLE001 - RecursionError, MemoryError, closed stdin
        if isinstance(e, KeyboardInterrupt):
            raise
        read_error = f"{e.__class__.__name__}: {e}"
    try:
        if not profile.should_run(name):
            return hookio.EXIT_ALLOW
        if read_error is not None:
            return hookio.deny(
                f"BLOCKED: {PROG} {name} could not read the hook payload ({read_error}), so "
                "it cannot judge this call. Retry the call, or ask the person who owns "
                "this project to look at it.")
        cfg = cfgmod.load(a.config, cfgmod.project_dir(payload))
        return fn(payload, oversized, cfg)
    except Exception as e:  # noqa: BLE001
        why = f"{e.__class__.__name__}: {e}"
        tool = payload.get("tool_name") if isinstance(payload, dict) else None
        guarded = _GUARDED_TOOLS.get(name, ())
        if name == "check-command" and cfg is not None:
            guarded = guarded + commands.shell_tools(cfg)
        if read_error is not None or tool in guarded:
            # A valid payload for a tool this guard protects, and the guard could
            # not judge it: allowing would turn any crash an input can provoke
            # into a bypass. Refuse, and say how to switch the guard off if the
            # crash is a kit bug blocking real work.
            if isinstance(e, OSError):
                return hookio.deny(
                    f"BLOCKED: {PROG} {name} could not read or write a file it needs to judge "
                    f"this {tool or 'call'} ({why}). That is the environment (permissions, a "
                    "missing path), not a kit bug. Fix it and retry.")
            return hookio.deny(
                f"BLOCKED: {PROG} {name} hit an internal error and could not judge this "
                f"{tool or 'call'} ({why}). The call is refused rather than allowed unjudged. "
                "Simplify or rephrase it and retry; if it is a real kit bug, report it.")
        print(f"{PROG} {name}: internal error on a call it does not guard; allowing ({why})",
              file=sys.stderr)
        return hookio.EXIT_ALLOW


#: What a registered hook runs. `python -m hook_integrity_kit` would put the working
#: directory first on sys.path, and Claude Code runs hooks in the project directory,
#: so a `hook_integrity_kit/` package (or a `json.py`) inside the project would run
#: in place of the kit, with the guards switched off. This program drops every
#: sys.path entry that is not an absolute path (the empty entry `-c` adds for the
#: working directory, and a relative PYTHONPATH entry) before it imports the kit.
#: `os` and `sys` are already loaded when it starts, so a file named os.py cannot
#: replace them. An ABSOLUTE PYTHONPATH entry is still trusted (THREAT_MODEL.md).
_HOOK_CODE = ("import os,sys;sys.path[:]=[p for p in sys.path if os.path.isabs(p)];"
              "from hook_integrity_kit.cli import main;sys.exit(main([\"{sub}\"]))")


def hook_command(py: str, sub: str) -> str:
    """The shell command that runs ``sub`` (a subcommand name) under interpreter ``py``."""
    return f"{shlex.quote(py)} -c {shlex.quote(_HOOK_CODE.format(sub=sub))}"


def _usable_interpreter(py: str) -> Optional[str]:
    """Why ``py`` cannot run the kit, or None. A registered guard whose interpreter is
    missing fails on every call, and with `onFailure: block` that blocks every one."""
    if not py.strip():
        return "the interpreter path is empty"
    if os.sep in py or (os.altsep and os.altsep in py):
        if not os.path.isfile(py):
            return f"{py} is not a file"
        if not os.access(py, os.X_OK):
            return f"{py} is not executable"
        return None
    return None if shutil.which(py) else f"{py} is not on PATH"


def cmd_install(a: argparse.Namespace) -> int:
    py = a.python if a.python is not None else sys.executable
    why = _usable_interpreter(py)
    if why:
        print(f"{PROG}: install refused: {why}. A guard registered with it would fail on "
              "every call, and onFailure=block would then refuse every tool call.",
              file=sys.stderr)
        return EXIT_USAGE
    tools = ["Bash"]
    for t in a.shell_tool:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", t):
            print(f"{PROG}: install refused: '{t}' is not a tool name", file=sys.stderr)
            return EXIT_USAGE
        if t not in tools:
            tools.append(t)

    def hook(sub: str, guard: bool = False) -> dict:
        h = {"type": "command", "command": hook_command(py, sub), "timeout": 30}
        if guard:
            # Claude Code lets a tool call through when a PreToolUse hook times
            # out, crashes or cannot start. "block" makes every such failure a
            # refusal (Claude Code >= 2.1.295), so a guard fails closed end to end.
            h["onFailure"] = "block"
        return h

    snippet = {"hooks": {
        "SessionStart": [{"matcher": "", "hooks": [hook("session-start")]}],
        "PreToolUse": [
            {"matcher": "|".join(tools), "hooks": [hook("check-command", guard=True)]},
            {"matcher": "Write|Edit|MultiEdit|NotebookEdit",
             "hooks": [hook("check-write", guard=True)]},
            {"matcher": "Write|Edit|MultiEdit", "hooks": [hook("check-gate-config", guard=True)]},
        ],
    }}
    # stdout is the JSON and nothing else, so `install > snippet.json` is a valid file.
    print("Merge the JSON below into .claude/settings.json yourself (this command "
          "writes nothing). The interpreter path in it is this machine's.", file=sys.stderr)
    print(json.dumps(snippet, indent=2))
    print("Then review every hook the project registers and run: hook-integrity-kit bless",
          file=sys.stderr)
    if len(tools) > 1:
        print("check-command judges only the tools named in `commands.shell_tools` in "
              ".claude/hook-integrity-kit.json (Bash is always judged); add "
              + ", ".join(json.dumps(t) for t in tools[1:]) + " there too. The names are not "
              "checked against Claude Code.", file=sys.stderr)
    return EXIT_OK


def cmd_rules(a: argparse.Namespace) -> int:
    try:
        project = _root(a.root) if a.root else cfgmod.project_dir() or Path.cwd()
    except manifest.NotEvaluable as e:
        print(f"{PROG}: rules failed: {e}", file=sys.stderr)
        return EXIT_NOT_EVALUABLE
    cfg = cfgmod.load(a.config, project)
    rules, ctx, _ = commands.active_rules(cfg)
    print("check-command:")
    for r in rules:
        print(f"  {r.id:36} {r.severity:8} {r.description}")
    print(f"  protected branches: {', '.join(ctx.protected_branches)}")
    hard, soft, settings_rule, _ = writes.active_rules(cfg)
    print("check-write (block):")
    for r in hard:
        print(f"  {r.id:36} {r.description}")
    if settings_rule:
        print(f"  {'claude-settings-hooks':36} edits that change a settings `hooks` block")
    print("check-write (note only):")
    for r in list(soft) + list(writes.CONTENT_WARNINGS):
        print(f"  {r.id:36} {r.description}")
    print("check-gate-config (protected basenames):")
    for name in sorted(gateconfig.protected_map(cfg)):
        print(f"  {name}")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    ap = _parser()
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:                  # argparse exits 2; 2 means NOT EVALUABLE here
        return EXIT_OK if e.code == 0 else EXIT_USAGE
    if a.cmd is None:
        ap.print_usage(sys.stderr)
        return EXIT_USAGE
    if a.cmd == "bless":
        return cmd_bless(a)
    if a.cmd == "verify":
        return cmd_verify(a)
    if a.cmd == "session-start":
        return cmd_session_start(a)
    if a.cmd == "check-command":
        return _guard(a, "check-command", commands.run)
    if a.cmd == "check-write":
        return _guard(a, "check-write", writes.run)
    if a.cmd == "check-gate-config":
        return _guard(a, "check-gate-config", gateconfig.run)
    if a.cmd == "install":
        return cmd_install(a)
    if a.cmd == "audit":
        from . import audit as audit_mod
        fmt = a.format or ("json" if a.json else "text")
        return audit_mod.main((a.root or Path.cwd()).resolve(), fmt == "json", jsonl=fmt == "jsonl",
                              strict=a.strict)
    if a.cmd == "rules":
        return cmd_rules(a)
    if a.cmd == "profile":
        try:
            root = _root(a.root) if a.root else Path.cwd()
        except manifest.NotEvaluable as e:
            print(f"{PROG}: profile failed: {e}", file=sys.stderr)
            return EXIT_NOT_EVALUABLE
        print(profile.profile_info(root, cfgmod.load(project=root)))
        return EXIT_OK
    return EXIT_USAGE
