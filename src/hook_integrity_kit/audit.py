"""`audit`: what a checkout will run on its own, read before anything in it runs. No baseline.

Opening a repository you did not write in an AI coding agent or an editor can run code before
you read any of it: Claude Code hooks (a `SessionStart` hook runs at the first session), other
command-bearing settings, project MCP servers, a VS Code task with `"runOn": "folderOpen"`, and
a devcontainer's lifecycle commands (`initializeCommand` runs on the HOST). The Mini Shai-Hulud
npm worm (2026-05) planted exactly the first and the fourth.

`audit` lists each of these with where it is declared, and flags:
* a command the PreToolUse guard rules would refuse (pipe-to-shell, `rm -rf /`, ...);
* a project script a hook runs whose text fetches from the network or runs fetched text;
* a task that runs when the folder opens, a host-side devcontainer command, and
  `enableAllProjectMcpServers` (every project MCP server approved without a prompt);
* a repo-local plugin's hooks by the same tests as a settings hook, the scripts a hook reaches
  through other scripts and imports, and a kit config that switches guard rules off.

and notes for review (`?`, not a failure): a `SessionStart` hook (it runs before the first
prompt), and a hook script that reaches the network without running fetched code.

It reads files only; it runs and writes nothing. Exit 0: nothing flagged (the list may still
be long: read it). Exit 1: something flagged. With ``--strict`` (opt-in) exit 1 also when ANY
item runs on its own, flagged or not. Exit 2: a config file could not be read, so the
list is incomplete (named).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

from . import commands, manifest

#: A script that reaches the network...
_NETWORK_FETCH = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b|\bfetch\s*\(|"
    r"\burllib\.request\b|\brequests\.(?:get|post)\b|\bhttps?://|\bnew\s+WebSocket\b", re.I)
#: ...and runs code it was not shipped with. Both together is a flag; network alone a note.
_RUNS_CODE = re.compile(
    r"\beval\(|\bexec\(|\(\s*eval\s*\)|\bnew\s+Function\(|\bFunction\(|"
    r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\bbase64\s+(?:-d|--decode)\b|\biex\b|"
    r"\bInvoke-Expression\b|\bchild_process\b|\bspawn\s*\(|\bexecSync\s*\(", re.I)
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
#: An env value under a name like this is a credential: the name is the finding, not the value.
_SECRET_NAME = re.compile(r"TOKEN|SECRET|PASSW|API_?KEY|CREDENTIAL|AUTH|HEADER|COOKIE", re.I)


def _shown(m: "re.Match") -> str:
    """A matched word for display: `fetch(` -> fetch, `(eval)` -> eval, `| sh` -> | sh."""
    return m.group(0).strip().strip("()").strip()


def _is_shell(rel: str, text: str) -> bool:
    if rel.lower().endswith(_SHELL_SUFFIXES):
        return True
    first = text.split("\n", 1)[0]
    return first.startswith("#!") and re.search(r"\b(?:ba|z|k|da)?sh\b", first) is not None


#: Hook events that fire when a session opens, before anyone types: a review note, not a flag
#: (many honest projects use one), so a reader of a long list sees which rows run unasked.
SESSION_OPEN_EVENTS = {"SessionStart": "runs when a session starts, before the first prompt"}

DEVCONTAINER_KEYS = ("initializeCommand", "onCreateCommand", "updateContentCommand",
                     "postCreateCommand", "postStartCommand", "postAttachCommand")


def _jsonc(text: str):
    """JSON with comments and trailing commas (VS Code's format). Comments are removed
    outside strings only."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def _cmd_text(v) -> str:
    """A devcontainer/task command: a string, a list of words, or an object of named
    commands."""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    if isinstance(v, dict):
        return " ; ".join(_cmd_text(x) for x in v.values())
    return ""


class Audit:
    def __init__(self, root: Path) -> None:
        self.root = root
        # (kind, where, what, flags, notes): flags fail the audit, notes are for review
        self.items: List[Tuple[str, str, str, List[str], List[str]]] = []
        self.unreadable: List[str] = []

    def load(self, rel: str, jsonc: bool = False):
        p = self.root / rel
        if not p.is_file():
            return None
        try:
            text = p.read_text(encoding="utf-8")
            return _jsonc(text) if jsonc else json.loads(text)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            self.unreadable.append(f"{rel}: {e.__class__.__name__}: {e}")
            return None

    def add(self, kind: str, where: str, what: str, flags: Optional[List[str]] = None,
            notes: Optional[List[str]] = None) -> None:
        self.items.append((kind, where, what, flags or [], notes or []))

    def judge(self, command: str) -> List[str]:
        hit = commands.check_command(command)
        return [f"{hit.id}: {hit.description}"] if hit is not None else []

    def script_flags(self, rel: str) -> Tuple[List[str], List[str]]:
        """(flags, notes) for a project script a hook runs. A script that fetches AND runs
        code is a flag; reaching the network alone is a note (honest hooks fetch too). The
        shell guard rules judge shell scripts only (a Python or JS file holds rule patterns,
        messages and data that are not commands), and skip comment lines."""
        p = self.root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [f"{rel}: could not be read"], []
        flags: List[str] = []
        notes: List[str] = []
        # comment lines are not code; they are blanked (line numbers kept) before the search
        code = "\n".join("" if ln.strip().startswith(("#", "//")) and not ln.startswith("#!")
                         else ln for ln in text.split("\n"))
        # a continued line is one command; same length, so offsets still give line numbers
        code = code.replace("\\\n", " \n")
        net = _NETWORK_FETCH.search(code)
        run = _RUNS_CODE.search(code)
        if net:
            line = text.count("\n", 0, net.start()) + 1
            if run:
                rline = text.count("\n", 0, run.start()) + 1
                flags.append(f"{rel}:{line} fetches from the network ({_shown(net)}) "
                             f"and runs code at line {rline} ({_shown(run)})")
            else:
                notes.append(f"{rel}:{line} reaches the network ({_shown(net)})")
        if _is_shell(rel, text):
            first, held = 0, ""
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    if not held:
                        continue
                first = first or i
                if s.endswith("\\") and not s.endswith("\\\\"):
                    held += s[:-1] + " "
                    continue
                s, at, held, first = held + s, first, "", 0
                hit = commands.check_command(s)
                if hit is not None:
                    flags.append(f"{rel}:{at} {hit.id}: {hit.description}")
        return flags, notes

    def reached(self, rels: List[str]) -> List[str]:
        """The project files these scripts reach through other scripts and imports, as `verify`
        follows them. What cannot be followed is named, never read as nothing."""
        shells = [r for r in rels if manifest._script_kind(self.root / r) == "shell"]
        pys = {r for r in rels if manifest._script_kind(self.root / r) == "python"}
        try:
            called, _s, called_py, _n = manifest.follow_shell_calls(self.root, shells)
            pys |= {r for r in called_py if (self.root / r).is_file()}
            imported, _n2, _src = manifest.import_walk(self.root, pys)
        except manifest.NotEvaluable as e:
            self.unreadable.append(f"what {', '.join(rels)} runs: {e}")
            return []
        return sorted((set(called) | set(imported)) - set(rels))

    def _list(self, rel: str, what: str, value) -> list:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        self.shape(rel, what)
        return []

    def hook_block(self, block: dict, rel: str, plugin_root: Optional[Path] = None,
                   prefix: str = "") -> None:
        for event, groups in block.items():
            if not isinstance(groups, list) or any(
                    not isinstance(g, dict) or not isinstance(g.get("hooks", []), list)
                    for g in groups):
                self.shape(rel, f"`hooks.{event}`")
        for event, entry in manifest._entries(block):
            cmd = " ".join(t for t in manifest._texts(entry) if t)
            if entry.get("type") not in (None, "command"):
                cmd = f"{entry.get('type')} {entry.get('url') or entry.get('prompt') or ''}".strip()
            flags = self.judge(cmd)
            notes: List[str] = []
            if event in SESSION_OPEN_EVENTS:
                notes.append(SESSION_OPEN_EVENTS[event])
            rels, _ext = manifest.script_refs(entry, self.root, plugin_root)
            for r in rels + self.reached(rels):
                f2, n2 = self.script_flags(r)
                flags += f2
                notes += n2
            self.add(f"Claude Code {prefix}hook {event}", rel, cmd, flags, notes)

    def plugins(self) -> None:
        """Repo-local plugins and frontmatter: the same surface `verify` reads."""
        audit = self

        class Listing(manifest.Registrations):
            def add_block(self, block, label, plugin_root=None, event_prefix=""):
                audit.hook_block(block, label.replace("plugin ", "", 1), plugin_root, "plugin ")
                super().add_block(block, label, plugin_root, event_prefix)

        regs = Listing(self.root)
        try:
            manifest.plugin_inventory(self.root, regs)
        except manifest.NotEvaluable as e:
            self.unreadable.append(str(e))
        for n in regs.not_checked:
            if "symlink" in n:
                self.unreadable.append(n)
        for rel in manifest.frontmatter_hook_files(self.root):
            self.add("Claude Code frontmatter hooks", rel, "declared in the file's frontmatter", [],
                     ["run while that skill or agent is active; not parsed here, so read the file"])

    def kit_config(self) -> None:
        """A kit config arrives with the checkout and is obeyed at once."""
        rel = ".claude/hook-integrity-kit.json"
        data = self.load(rel)
        if data is None:
            return
        if not isinstance(data, dict):
            self.shape(rel, "the file")
            return
        for name in ("commands", "writes", "gate_config"):
            sec = data.get(name)
            off = self._list(rel, f"`{name}.disable`", sec.get("disable")) if isinstance(sec, dict) else []
            off = [str(x) for x in off]
            if off:
                self.add(f"hook-integrity-kit config {name}.disable", rel, ", ".join(off),
                         ["this checkout switches guard rules off for whoever opens it"])

    def shape(self, rel: str, what: str) -> None:
        """A config that parses but has the wrong shape: what it declares cannot be listed."""
        self.unreadable.append(f"{rel}: {what} has an unexpected shape")

    def claude(self) -> None:
        for name in ("settings.json", "settings.local.json"):
            rel = f".claude/{name}"
            data = self.load(rel)
            if data is None:
                continue
            if not isinstance(data, dict):
                self.shape(rel, "the file")
                continue
            hooks = data.get("hooks") or {}
            if not isinstance(hooks, dict):
                self.shape(rel, "`hooks`")
                hooks = {}
            self.hook_block(hooks, rel)
            for key in manifest.COMMAND_SETTINGS_KEYS:
                if key in data:
                    v = data[key]
                    cmd = v.get("command", "") if isinstance(v, dict) else str(v)
                    self.add(f"Claude Code setting {key}", rel, cmd, self.judge(cmd))
            self.permissions(rel, data)
            env = data.get("env")
            for key, value in (env.items() if isinstance(env, dict) else ()):
                shown = "(value not shown)" if _SECRET_NAME.search(str(key)) else value
                if manifest.is_exec_env(key):
                    self.add("Claude Code setting env", rel, f"{key}={shown}",
                             ["changes what code or traffic runs on this machine"])
                else:
                    # Every env key is listed (verify pins them all); only the names known to
                    # steer code or traffic are flagged.
                    self.add("Claude Code setting env", rel, f"{key}={shown}", [],
                             ["sets an environment variable for this project; verify pins it, "
                              "and this name is not known to steer code or traffic"])
            for key in ("enabledPlugins", "extraKnownMarketplaces"):
                if data.get(key):
                    self.add(f"Claude Code setting {key}", rel, json.dumps(data[key])[:200],
                             ["plugins carry hooks that run on their own"])
            if data.get("enableAllProjectMcpServers") is True:
                self.add("Claude Code setting enableAllProjectMcpServers", rel, "true",
                         ["every MCP server in .mcp.json is approved without a prompt"])
            for s in self._list(rel, "`enabledMcpjsonServers`", data.get("enabledMcpjsonServers")):
                self.add("Claude Code setting enabledMcpjsonServers", rel, str(s))

    def permissions(self, rel: str, data: dict) -> None:
        """What the repository lets the agent do without asking. A cloned repository that sets
        these decides for whoever opens it (CVE-2026-33068: `bypassPermissions` in a project's
        settings skipped the trust prompt)."""
        if data.get("disableAllHooks") is True:
            self.add("Claude Code setting disableAllHooks", rel, "true",
                     ["no hook runs while this is set, guards and integrity checks included"])
        perms = data.get("permissions")
        if not isinstance(perms, dict):
            if perms is not None:
                self.shape(rel, "`permissions`")
            return
        mode = perms.get("defaultMode")
        if mode == "bypassPermissions":
            self.add("Claude Code permission defaultMode", rel, mode,
                     ["every action is approved without a prompt"])
        elif mode == "acceptEdits":
            self.add("Claude Code permission defaultMode", rel, mode, [],
                     ["file edits are approved without a prompt"])
        for r in self._list(rel, "`permissions.allow`", perms.get("allow")):
            if not isinstance(r, str):
                continue
            if manifest._broad_rule(r):
                self.add("Claude Code allow rule", rel, r,
                         ["a whole tool, or a command that runs anything, is allowed without a prompt"])
            elif manifest.egress_rule(r):
                self.add("Claude Code allow rule", rel, manifest.shown_rule(r),
                         ["a network command is allowed without a prompt"])
        for d in self._list(rel, "`permissions.additionalDirectories`", perms.get("additionalDirectories")):
            if isinstance(d, str):
                self.add("Claude Code additional directory", rel, d, [],
                         ["the agent may read and write outside the project here"])

    def mcp(self) -> None:
        data = self.load(".mcp.json")
        if data is None:
            return
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            self.shape(".mcp.json", "`mcpServers`")
            return
        for name, s in sorted(servers.items()):
            if not isinstance(s, dict):
                self.shape(".mcp.json", f"server '{name}'")
                continue
            args = self._list(".mcp.json", f"`args` of server '{name}'", s.get("args"))
            cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in args]).strip()
            what = cmd or str(s.get("url", ""))
            self.add(f"MCP server {name}", ".mcp.json", what, self.judge(cmd) if cmd else [])

    def vscode(self) -> None:
        data = self.load(".vscode/tasks.json", jsonc=True)
        if data is None:
            return
        tasks = data.get("tasks", []) if isinstance(data, dict) else None
        if not isinstance(tasks, list):
            self.shape(".vscode/tasks.json", "`tasks`")
            return
        for i, t in enumerate(tasks):
            if not isinstance(t, dict) or not isinstance(t.get("runOptions", {}), dict):
                self.shape(".vscode/tasks.json", f"task {i}")
                continue
            run_on = (t.get("runOptions") or {}).get("runOn")
            if run_on != "folderOpen":
                continue
            args = self._list(".vscode/tasks.json", f"`args` of task {i}", t.get("args"))
            cmd = " ".join([_cmd_text(t.get("command"))] + [_cmd_text(a) for a in args])
            self.add(f"VS Code task '{t.get('label', '?')}'", ".vscode/tasks.json", cmd.strip(),
                     ["runs when the folder opens (runOn: folderOpen)"] + self.judge(cmd))

    def devcontainer(self) -> None:
        # The spec also allows one folder level: .devcontainer/<folder>/devcontainer.json.
        subs: List[str] = []
        try:
            subs = sorted(f".devcontainer/{d.name}/devcontainer.json"
                          for d in (self.root / ".devcontainer").iterdir()
                          if d.is_dir() and not d.is_symlink())
        except OSError:
            pass
        for rel in (".devcontainer/devcontainer.json", ".devcontainer.json", *subs):
            data = self.load(rel, jsonc=True)
            if not isinstance(data, dict):
                if data is not None:
                    self.shape(rel, "the file")
                continue
            for key in DEVCONTAINER_KEYS:
                if key in data:
                    cmd = _cmd_text(data[key])
                    flags = (["runs on the host, before the container exists"]
                             if key == "initializeCommand" else []) + self.judge(cmd)
                    self.add(f"devcontainer {key}", rel, cmd, flags)

    def run(self) -> "Audit":
        for section in (self.claude, self.plugins, self.kit_config, self.mcp, self.vscode,
                        self.devcontainer):
            # One value of a wrong shape must not cost the rest of the list, or the RUN event.
            try:
                section()
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                self.unreadable.append(f"{section.__name__}: a value has an unexpected shape "
                                       f"({e.__class__.__name__}: {e})")
        return self


def main(root: Path, as_json: bool = False, jsonl: bool = False, strict: bool = False) -> int:
    if not root.is_dir():
        msg = (f"{root} does not exist or is not a directory; nothing was audited. "
               "This is not a pass.")
        if jsonl:
            from . import events
            print(events.dumps(events.from_audit([], [msg], str(root))))
        else:
            print(f"NOT EVALUABLE: {msg}")
        return 2
    a = Audit(root).run()
    flagged = sum(1 for _k, _w, _x, f, _n in a.items if f)
    # --strict (opt-in): anything that runs on its own fails the audit, flagged or not.
    strict_fail = strict and bool(a.items)
    if jsonl:
        from . import events
        print(events.dumps(events.from_audit(a.items, a.unreadable, str(root), strict=strict)))
    elif as_json:
        print(json.dumps({"root": str(root), "items": [
            {"kind": k, "where": w, "what": x, "flags": f, "notes": n}
            for k, w, x, f, n in a.items],
            "unreadable": a.unreadable, "flagged": flagged, "strict": strict},
            indent=2))
    else:
        if not a.items and not a.unreadable:
            print(f"audit: {root}: nothing here runs on its own (Claude Code hooks, plugin hooks "
                  "and command settings, .mcp.json, VS Code folderOpen tasks, devcontainer commands)")
        for kind, where, what, flags, notes in a.items:
            print(f"AUTO-RUN {kind} ({where}): {what}")
            for f in flags:
                print(f"  ! {f}")
            for n in notes:
                print(f"  ? {n}")
        for u in a.unreadable:
            print(f"NOT EVALUABLE: {u} (what it declares is not listed)")
        print(f"audit: {len(a.items)} item(s) run on their own, {flagged} flagged"
              + (f", {len(a.unreadable)} file(s) unreadable" if a.unreadable else "")
              + (f"; strict: {len(a.items)} item(s) run on their own; review each before "
                 "opening this checkout" if strict_fail else ""))
    if a.unreadable:
        return 2
    return 1 if flagged or strict_fail else 0
