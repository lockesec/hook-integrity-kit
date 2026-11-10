"""The integrity baseline: build it (``bless``) and compare against it (``verify``).

WHY. Claude Code runs the hooks a project registers automatically, and a hook is
only a path in a settings file: change the script behind the path, or add one
line to the ``hooks`` block, and the next session runs the new code with no
prompt. Project files have already been the delivery vehicle for code execution
in Claude Code (see THREAT_MODEL.md). This module turns a silent change to that
auto-executing surface into a named, reviewable event.

WHAT THE BASELINE COVERS (``.claude/hook-integrity.json`` by default):

* the ``hooks`` block of ``.claude/settings.json`` and of
  ``.claude/settings.local.json``, each hashed together with the WHOLE ``env``
  block (every key name and a digest of its value, never the value; see ``pinned_env``) and
  the keys that switch hooks off or narrow them (``disableAllHooks``, ``allowManagedHooksOnly``,
  ...; see ``HOOK_CONTROL_KEYS``). Other settings churn (permissions, model) never reads as drift;
* every command-hook registration, from the settings files AND from repo-local
  plugins (``hooks/hooks.json`` at any depth under ``.claude/plugins``, and the
  ``hooks`` field of each ``.claude-plugin/plugin.json``), run through ONE
  resolver: ``${CLAUDE_PROJECT_DIR}`` and ``${CLAUDE_PLUGIN_ROOT}`` references,
  project-relative paths, and absolute paths;
* for every Python entry point (a ``.py`` file, a file run by a ``python``
  interpreter token, or a file whose shebang names python), whatever Python
  itself would load for each top-level import from the entry point's REAL
  directory (``sys.path[0]`` is the resolved script directory): a package, a
  source module, a sourceless ``.pyc`` or an extension module, in the path
  finder's order, walked transitively;
* the bytecode caches of those modules: a cache this interpreter would load is
  compiled from its source and compared; a cache for another interpreter is
  pinned by its code payload at bless time;
* the kit's own config file, any ``integrity.extra_files`` globs, and the kit's
  own installed source files and bytecode (so a swapped guard is drift too);
* optionally (``bless --include-global``), the user-level ``~/.claude``
  surface. That half is WARN-ONLY: ``~/.claude`` changes whenever an unrelated
  tool is installed, and a gate that fires on each would train people to
  dismiss it. It is still reported by name.

WHAT IT DOES NOT COVER, and says so (``NOT CHECKED`` lines in ``verify`` and
``bless``) wherever it can see the surface:

* hook handlers that are not ``type: "command"`` (``http``, ``mcp_tool``,
  ``prompt``, ``agent``), from any origin. Their DEFINITION is pinned, so
  editing one is drift; what the URL, MCP tool or model does is not;
* hooks declared in the frontmatter of skills and subagents. The files are found
  and named, not parsed or hashed;
* other settings keys that run a command (``statusLine``, ``apiKeyHelper``, ...),
  MCP server configs (``.mcp.json``, a plugin's ``mcpServers``), and marketplace
  entries that declare hooks;
* Python imports that resolve outside the entry point's directory (installed
  packages, ``sys.path`` changes, dynamic imports), shell ``source`` lines, and
  compiled modules' own imports;
* commands that run no file inside the project;
* surfaces outside the project, named by presence when they exist on this machine:
  the user's installed plugins, user-level settings hooks (unless the baseline
  covers ``~/.claude``), and managed settings files.

NEVER REPORTED (the kit does not look): helpers loaded by other languages,
remote-managed settings, MDM and registry policy, ``~/.claude.json``, user-level
skills and agents, settings passed on the command line, a relocated
``CLAUDE_CONFIG_DIR``. docs/coverage.md lists them.

HONEST STATES. The result is never "clean" by default:

* a registered script that does not exist is recorded with a null hash and
  stays a finding until it is resolved;
* a settings file, plugin registration, hooked Python file or bytecode cache
  that cannot be read or parsed makes the whole check NOT EVALUABLE: skipping
  it would hide everything behind it;
* on-disk hook scripts that nothing registers or imports are listed as
  informational only;
* scripts registered by absolute path outside the project are named as
  "not checked", never silently skipped;
* a baseline that predates global coverage says "not covered", not "clean".

RE-BASELINING IS DELIBERATELY MANUAL. Run ``hook-integrity-kit bless`` after
reviewing a legitimate hook change, and commit the baseline with the hook diff.
Never regenerate it automatically (for example at session end): an automatic
rebuild would bless a mid-session malicious edit before the next check could
see it.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import marshal
import os
import re
import shlex
import sys
import sysconfig
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

BASELINE_REL = Path(".claude") / "hook-integrity.json"
SETTINGS_RELS = (Path(".claude") / "settings.json", Path(".claude") / "settings.local.json")
HOOKS_DIR_REL = Path(".claude") / "hooks"
PLUGINS_DIR_REL = Path(".claude") / "plugins"
CONFIG_REL = Path(".claude") / "hook-integrity-kit.json"

EVENT_PLUGIN_REG = "_plugin_registration"
EVENT_FRONTMATTER = "_frontmatter_hooks"
EVENT_IMPORTED = "_imported_by"
EVENT_EXTRA = "_extra"
EVENT_KIT_CONFIG = "_kit_config"
EVENT_MCP = "_mcp"

SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
                   ".rb", ".pl", ".ps1"}
_HOOK_SUFFIXES = {".py", ".sh"}
_SHELL_SUFFIXES = {".sh", ".bash", ".zsh"}
_SKIP_DIRS = {"__pycache__"}
_KIT_MARKERS = ("hook_integrity_kit", "hook-integrity-kit")

# A quote may sit between the variable and the slash: the hooks reference's own
# examples write "$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh.
# the project-dir variable, also with a default (`${CLAUDE_PROJECT_DIR:-.}`); one pattern for every reader
_PDIR = r"(?:\$\{CLAUDE_PROJECT_DIR(?::?[-=?+][^}]*)?\}|\$CLAUDE_PROJECT_DIR(?![\w]))"
_PROJECT_DIR_REF = re.compile(_PDIR + r"[\"']?/(.+)$")
_PLUGIN_ROOT_REF = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?[\"']?/(.+)$")
_PY_INTERP = re.compile(r"(?:^|/)(?:python|pypy)(?:\d+(?:\.\d+)*)?[tw]?(?:\.exe)?$")
_SH_INTERP = re.compile(r"(?:^|/)(?:r?(?:ba|z|da|k|a|mk|pdk)?sh\d*|bash-?\d+(?:\.\d+)*)$")
_PY_OPTS_WITH_ARG = {"-W", "-X", "--check-hash-based-pycs"}

#: Settings keys, other than ``hooks``, whose value Claude Code runs as a command.
COMMAND_SETTINGS_KEYS = ("statusLine", "apiKeyHelper", "awsAuthRefresh",
                         "awsCredentialExport", "otelHeadersHelper", "fileSuggestion",
                         "subagentStatusLine")

BASELINE_VERSION = 2


class NotEvaluable(Exception):
    """The check could not look (no project root, unreadable settings)."""


# ── primitives ───────────────────────────────────────────────────────────────

def find_project_root(start: Optional[Path] = None) -> Path:
    """Nearest ancestor holding a ``.claude`` directory or ``.git``."""
    p = (start or Path.cwd()).resolve()
    if p.is_file():
        p = p.parent
    for cand in (p, *p.parents):
        if (cand / ".claude").is_dir() or (cand / ".git").exists():
            return cand
    raise NotEvaluable(f"no project root above {p} (no .claude/ or .git)")


def _exec_bit(path: Path) -> Optional[bool]:
    """Whether the file can be executed. `chmod -x` switches a hook off with the same bytes.
    None where the bit means nothing (Windows) or the file cannot be read."""
    if os.name != "posix":
        return None
    try:
        return bool(path.stat().st_mode & 0o111)
    except OSError:
        return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _py_version() -> str:
    return f"{sys.version_info[0]}.{sys.version_info[1]}"


# ── settings: the hooks block plus the env that steers interpreters ─────────

_EXEC_ENV_EXACT = {"PATH", "ENV", "ZDOTDIR", "SHELL", "SHELLOPTS", "BASHOPTS", "IFS",
                   "PS4", "PROMPT_COMMAND", "HOME", "XDG_CONFIG_HOME", "VIRTUAL_ENV",
                   "CONDA_PREFIX", "PERLLIB", "CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT",
                   # the kit's own control variables: a settings env that sets
                   # them switches the guards off or opens the edit override
                   "DISABLED_HOOKS", "HOOK_PROFILE",
                   # other runtimes' startup/option variables, and the API endpoint
                   "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
                   "PHPRC", "PHP_INI_SCAN_DIR", "LUA_PATH", "LUA_CPATH", "LUA_INIT",
                   "DOTNET_STARTUP_HOOKS", "GCONV_PATH", "GLIBC_TUNABLES", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
                   "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
                   # OpenSSL loads a config file, providers and engines named here, so a
                   # shared library runs in any process that links it (Python ssl, curl, git)
                   "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES",
                   # what Claude Code itself runs or loads through the environment
                   "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_ENV_FILE", "CLAUDE_CONFIG_DIR",
                   # where the traffic goes, and whose certificates it trusts
                   "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE",
                   "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
_EXEC_ENV_PREFIXES = ("PYTHON", "BASH_", "LD_", "DYLD_", "PERL5", "RUBY", "GEM_",
                      "NODE_", "GIT_", "UV_", "HOOK_KIT_", "HOOK_INTEGRITY_")


#: ``NODE_*`` names that pick a configuration profile and load no code.
_NOT_EXEC_ENV = {"NODE_ENV"}


def is_exec_env(key: str) -> bool:
    """An env key KNOWN to change which code a hook's interpreter or shell runs, or where
    traffic goes (a search path, a preload, a startup file, a proxy). ``audit`` FLAGS these (`!`).
    It is no longer the pin set: ``verify`` and ``check-write`` pin every ``env`` key
    (``pinned_env``), because no name list can name every tool's config variable
    (``OPENSSL_CONF``, ``PIP_INDEX_URL``, ``ANTHROPIC_CUSTOM_HEADERS``, ...). Whether Claude
    Code hands the settings ``env`` block to hook processes is not something this kit can
    verify, so it assumes it may."""
    k = key.upper()
    if k in _NOT_EXEC_ENV:
        return False
    return k in _EXEC_ENV_EXACT or k.startswith(_EXEC_ENV_PREFIXES)


def exec_env(env: object) -> Dict[str, object]:
    """The subset of an ``env`` block ``is_exec_env`` names (what ``audit`` flags)."""
    if not isinstance(env, dict):
        return {}
    return {k: v for k, v in env.items() if isinstance(k, str) and is_exec_env(k)}


def pinned_env(env: object) -> Dict[str, str]:
    """EVERY key of a settings ``env`` block, as {name: SHA-256 of the canonical value}. This is
    what goes into the settings hash: adding, changing or removing any key moves it, and the
    baseline holds digests only, so a value (it may be a credential) is never stored or printed.
    Anything but an object pins nothing."""
    if not isinstance(env, dict):
        return {}
    return {k: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"),
                                         default=str).encode("utf-8")).hexdigest()
            for k, v in env.items() if isinstance(k, str)}


def load_settings(settings_path: Path) -> dict:
    """A settings file as a dict. An absent file is ``{}``. A file that is not a
    JSON object, or whose ``hooks`` is not an object, raises NotEvaluable."""
    if not settings_path.is_file():
        return {}
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise NotEvaluable(f"settings unreadable: {settings_path}: {e}") from e
    if not isinstance(data, dict):
        raise NotEvaluable(f"settings is not a JSON object: {settings_path}")
    hooks = data.get("hooks") or {}
    if not isinstance(hooks, dict):
        raise NotEvaluable(f"`hooks` is not an object in {settings_path}")
    return data


def load_hooks_block(settings_path: Path) -> dict:
    """The ``hooks`` block of a settings file. An absent file is an empty block."""
    return load_settings(settings_path).get("hooks") or {}


def canonical_hooks_hash(hooks_block: dict) -> str:
    """Hash of the hooks block alone, canonicalized so key order, formatting and
    unrelated settings keys can never move it."""
    canon = json.dumps(hooks_block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


#: Settings keys, other than ``hooks`` and ``env``, that decide WHETHER hooks run or
#: which hook handlers are allowed to. ``disableAllHooks`` and ``allowManagedHooksOnly``
#: are documented in the Claude Code settings reference; ``allowedHttpHookUrls`` and
#: ``httpHookAllowedEnvVars`` are the allow-lists for HTTP hooks as that reference
#: describes them. This kit could not check the names against the live documentation
#: when it was written, so an unknown or renamed key is a gap: docs/coverage.md says so.
HOOK_CONTROL_KEYS = ("disableAllHooks", "allowManagedHooksOnly", "allowedHttpHookUrls",
                     "httpHookAllowedEnvVars",
                     # plugins carry hooks, so enabling one changes what runs
                     "enabledPlugins", "extraKnownMarketplaces"
                     ) + COMMAND_SETTINGS_KEYS   # commands Claude Code runs on its own (statusLine, ...)


def hook_controls(data: object) -> Dict[str, object]:
    """The hook-suppressing / hook-scoping keys present in a settings object."""
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in HOOK_CONTROL_KEYS if k in data}


def settings_surface_hash(hooks_block: dict, env_exec: Dict[str, object],
                          controls: Optional[Dict[str, object]] = None) -> str:
    """The hooks block plus the whole ``env`` block (``pinned_env``: name and value digest)
    plus the hook-control keys. With neither extra it equals ``canonical_hooks_hash``, so adding one is
    a change."""
    if not env_exec and not controls:
        return canonical_hooks_hash(hooks_block)
    body: Dict[str, object] = {"hooks": hooks_block}
    if env_exec:
        body["env"] = env_exec
    if controls:
        body["hook_controls"] = controls
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def settings_hash(data: dict) -> str:
    return settings_surface_hash(data.get("hooks") or {}, pinned_env(data.get("env")),
                                 hook_controls(data))


# ── one registration resolver for settings and plugins ──────────────────────

def _entries(hooks_block: dict):
    """(event, entry) for every hook entry, tolerating malformed groups."""
    for event, groups in sorted(hooks_block.items()):
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for entry in group.get("hooks", []) or []:
                if isinstance(entry, dict):
                    yield event, entry


def _texts(entry: dict) -> List[str]:
    """The command and args of one entry. Claude Code accepts both the shell
    form (``command`` only) and the exec form (``command`` plus ``args``)."""
    texts = [str(entry.get("command", ""))]
    texts += [str(a) for a in entry.get("args", []) or []]
    return texts


def _unquote(tok: str) -> str:
    return tok.replace('"', "").replace("'", "")


_PUNCT = frozenset("();<>|&")


def _is_op(word: str) -> bool:
    """A shell operator token (``&&``, ``;``, ``|``, a redirect, a parenthesis)."""
    return bool(word) and all(c in _PUNCT for c in word)


def _shell_words(text: str) -> List[str]:
    """``text`` split into words the way a POSIX shell does: quotes and backslash
    escapes are honoured (``"my hooks/a.py"``, ``my\\ hooks/a.py``) and the
    operators ``&&``, ``;``, ``|`` come out as words of their own. Text that does
    not tokenize (an unclosed quote) falls back to a whitespace split."""
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return [t for t in (_unquote(x) for x in text.split()) if t]


def _cd_apply(cur: Optional[str], tok: str, root: Path, plugin_root: Optional[Path]
              ) -> Optional[str]:
    """The project-relative directory after ``cd tok`` from ``cur`` ('' is the project
    root), or None when it cannot be placed inside the project (a variable, a glob,
    ``~``, a path outside, ``..`` out of the project, ``cd -``)."""
    if cur is None:
        return None
    if not tok or tok == "-" or any(c in tok for c in "$`*?[~{"):
        if tok and (_var_path(tok, root, plugin_root) is not None
                    or _PROJECT_DIR_ONLY.match(tok)):
            return _cwd_rel(tok, root, plugin_root)
        return None
    if tok.startswith("/"):
        return _cwd_rel(tok, root, plugin_root)
    joined = Path(os.path.normpath(os.path.join(cur, tok))).as_posix()
    if joined == ".":
        return ""
    return None if joined == ".." or joined.startswith("../") else joined


def _cd_command(words: List[str], i: int, cur: Optional[str], root: Path,
                plugin_root: Optional[Path]) -> Tuple[Optional[str], int]:
    """``words[i]`` is ``cd`` or ``pushd``. (directory afterwards, index after the
    command's words). Options other than ``-L``/``-e`` (``-P`` resolves symlinks),
    ``pushd -n``, ``+N``, no directory, or ``cd -`` make the result None: the new
    directory is not known."""
    j = i + 1
    ok = True
    while j < len(words) and not _is_op(words[j]) and words[j].startswith(("-", "+")) \
            and words[j] != "-":
        if words[j] == "--":
            j += 1
            break
        if words[j] not in ("-L", "-e"):
            ok = False
        j += 1
    if j >= len(words) or _is_op(words[j]):
        return None, j
    tok = words[j]
    j += 1
    while j < len(words) and not _is_op(words[j]):          # extra words: not a plain cd
        ok = False
        j += 1
    return (_cd_apply(cur, tok, root, plugin_root) if ok else None), j


def _entry_words(entry: dict, root: Optional[Path] = None, plugin_root: Optional[Path] = None
                 ) -> List[Tuple[str, Optional[str]]]:
    """(word, project-relative directory the word is relative to) for one
    registration; the directory is None when a ``cd`` put it somewhere the kit cannot
    place. The ``command`` is split like a shell line; ``cd DIR`` and ``pushd DIR``
    before a ``&&`` / ``;`` move the words after them, a ``( ... )`` subshell restores
    the directory when it closes, and ``popd`` pops the ``pushd`` stack. ``args`` (the
    exec form) are literal words, never split, and run in the project directory."""
    root = root if root is not None else Path("/")
    out: List[Tuple[str, Optional[str]]] = []
    toks = _shell_words(str(entry.get("command", "")))
    cwd: Optional[str] = ""
    scopes: List[Optional[str]] = []
    dirs: List[Optional[str]] = []
    at_start, i = True, 0
    while i < len(toks):
        w = toks[i]
        if _is_op(w):
            for ch in w:
                if ch == "(":
                    scopes.append(cwd)
                elif ch == ")" and scopes:
                    cwd = scopes.pop()
            at_start = True
            i += 1
            continue
        if at_start and w in ("if", "then", "else", "elif", "do", "while", "until", "!", "{"):
            i += 1
            continue
        if at_start and w in ("cd", "pushd"):
            if w == "pushd":
                dirs.append(cwd)
            cwd, i = _cd_command(toks, i, cwd, root, plugin_root)
            continue
        if at_start and w == "popd":
            cwd = dirs.pop() if dirs else None
            i += 1
            while i < len(toks) and not _is_op(toks[i]):
                i += 1
            continue
        out.append((w, cwd))
        at_start = False
        i += 1
    out += [(str(a), "") for a in entry.get("args", []) or []]
    return out


def is_kit_entry(entry: dict) -> bool:
    return any(m in t for t in _texts(entry) for m in _KIT_MARKERS)


def _rel_or_none(path: Path, root: Path) -> Optional[str]:
    try:
        return Path(os.path.normpath(path)).relative_to(root).as_posix()
    except ValueError:
        return None


_PROJECT_DIR_ONLY = re.compile(_PDIR + r"/?$")


def _var_path(tok: str, root: Path, plugin_root: Optional[Path]) -> Optional[Path]:
    m = re.match(_PDIR + r"/(.+)$", tok)
    if m:
        return root / m.group(1)
    m = re.match(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/(.+)$", tok)
    if m and plugin_root is not None:
        return plugin_root / m.group(1)
    return None


def _cwd_rel(cd: str, root: Path, plugin_root: Optional[Path]) -> Optional[str]:
    """The project-relative directory a ``cd DIR`` named: '' for none or the project
    root, None when it cannot be placed inside the project."""
    if not cd:
        return ""
    if _PROJECT_DIR_ONLY.match(cd):
        return ""
    p = _var_path(cd, root, plugin_root)
    if p is None:
        if "$" in cd or "`" in cd:
            return None
        p = Path(os.path.expandvars(os.path.expanduser(cd)))
        p = p if p.is_absolute() else root / p
    rel = _rel_or_none(p, root)
    if rel is None or rel.startswith(".."):
        return None
    return "" if rel == "." else rel


def _join(cwd: Optional[str], tok: str) -> str:
    return Path(os.path.normpath(os.path.join(cwd, tok) if cwd else tok)).as_posix()


def _ref_piece(piece: str, whole: bool, cwd: Optional[str], root: Path,
               plugin_root: Optional[Path], rels: List[str], external: List[str],
               unplaced: Optional[List[str]] = None) -> None:
    """Classify one word (or, for a word holding blanks, the whole word and then each
    blank-separated piece of it). A whole word holding blanks counts only when it
    names a file that exists: ``"-c 'a && b'"`` is a shell string, not a path."""
    if not whole:
        piece = piece.rstrip(";|&)")
    if not piece:
        return
    if not whole and re.search(r"[*?\[{]", piece.replace("${", "")):
        return                     # a glob names no one file; the registration's note says so
    m = _PROJECT_DIR_REF.search(piece)
    if m:
        rel = Path(os.path.normpath(_unquote(m.group(1)))).as_posix()
        if not whole or (root / rel).is_file():
            rels.append(rel)
        return
    if plugin_root is not None:
        m = _PLUGIN_ROOT_REF.search(piece)
        if m:
            p = Path(os.path.normpath(plugin_root / _unquote(m.group(1))))
            if whole and not p.is_file():
                return
            rel = _rel_or_none(p, root)
            if rel is not None:
                rels.append(rel)
            else:
                external.append(str(p))
            return
    if "CLAUDE_PROJECT_DIR" in piece or "CLAUDE_PLUGIN_ROOT" in piece:
        return
    p = Path(os.path.expandvars(os.path.expanduser(piece)))
    if cwd is None and not p.is_absolute():
        # a `cd` put the words that follow somewhere the kit cannot place: a relative
        # script there is NOT the file of that name at the project root
        if p.suffix in SCRIPT_SUFFIXES and unplaced is not None:
            unplaced.append(piece)
        return
    if p.suffix not in SCRIPT_SUFFIXES:
        inside = p if p.is_absolute() else root / _join(cwd, piece)
        rel = _rel_or_none(inside, root)
        if rel is not None and not rel.startswith("..") and inside.is_file():
            rels.append(rel)
        return
    if p.is_absolute():
        if whole and not p.is_file():
            return
        rel = _rel_or_none(p, root)
        if rel is not None:
            rels.append(rel)
        else:
            external.append(str(p))
    else:
        rel = _join(cwd, piece)
        if whole and not (root / rel).is_file():
            return
        rels.append(rel)


def script_refs_full(entry: dict, root: Path, plugin_root: Optional[Path] = None
                     ) -> Tuple[List[str], List[str], List[str]]:
    """(project-relative scripts, external absolute scripts, scripts run after a ``cd``
    the kit cannot place) one entry runs.

    The command is read like a shell line (quotes, backslash escapes, ``cd`` /
    ``pushd`` / ``popd`` and subshells); ``args`` are literal words. ``${CLAUDE_PROJECT_DIR}/x``
    references (and, for a plugin registration, ``${CLAUDE_PLUGIN_ROOT}/x``) are always
    returned, even when the file is missing: a registered-but-missing script is
    itself a finding. Other words count when they have a script suffix, OR when they
    name an existing file inside the project whatever its suffix: ``bash
    .claude/hooks/run`` runs ``run``, and a suffix allow-list alone let that file
    change unseen. A word that holds blanks (a path with a space, or a ``-c`` string)
    is tried whole, as a path that must exist, and then piece by piece. A relative
    script after a ``cd`` to a place the kit cannot name (a variable, ``-P``, outside
    the project) is returned in the third list, never resolved against the root.
    """
    rels: List[str] = []
    external: List[str] = []
    unplaced: List[str] = []
    for tok, cwd in _entry_words(entry, root, plugin_root):
        if any(c.isspace() for c in tok):
            before = len(rels) + len(external) + len(unplaced)
            _ref_piece(tok, True, cwd, root, plugin_root, rels, external, unplaced)
            if len(rels) + len(external) + len(unplaced) > before:
                continue                      # the whole word is the path
            for piece in tok.split():
                _ref_piece(piece, False, cwd, root, plugin_root, rels, external, unplaced)
        else:
            _ref_piece(tok, False, cwd, root, plugin_root, rels, external, unplaced)
    return rels, external, unplaced


def script_refs(entry: dict, root: Path, plugin_root: Optional[Path] = None
                ) -> Tuple[List[str], List[str]]:
    """(project-relative scripts, external absolute scripts) one entry runs; see
    ``script_refs_full``."""
    rels, external, _ = script_refs_full(entry, root, plugin_root)
    return rels, external


# ── interpreter command lines, parsed per interpreter family ─────────────────
#
# One option table does not fit all: ``-e`` is an inline program for perl, ruby and
# node but ``errexit`` for a shell; ``-o`` takes an argument in a shell and ``-c`` is
# the only inline-program option there; ``-euo pipefail`` is a cluster whose ``o``
# consumes the next word. Each family names the option letters that END the options
# with an inline program (``inline``), read the program from stdin (``stdin``), take
# the next word (``arg``), name the script operand themselves (``file``), or load
# code the kit cannot follow (``unsure``). Anything not in a table is a plain flag.

class _Family:
    def __init__(self, name, inline="", stdin="", arg="", file="", unsure="",
                 long_inline=(), long_arg=(), long_unsure=(), plus_opts=False):
        self.name, self.inline, self.stdin, self.arg = name, inline, stdin, arg
        self.file, self.unsure = file, unsure
        self.long_inline, self.long_arg, self.long_unsure = (
            frozenset(long_inline), frozenset(long_arg), frozenset(long_unsure))
        self.plus_opts = plus_opts


_FAMILIES = {
    "python": _Family("python", inline="cm", arg="WX", long_arg=("--check-hash-based-pycs",)),
    "sh": _Family("shell", inline="c", stdin="s", arg="oO", long_arg=("--rcfile", "--init-file"),
                  plus_opts=True),
    "node": _Family("node", inline="ep", arg="C", long_inline=("--eval", "--print"),
                    long_arg=("--input-type", "--env-file", "--conditions", "--title"),
                    long_unsure=("--require", "--import", "--loader", "--experimental-loader"),
                    unsure="r"),
    "ruby": _Family("ruby", inline="e", arg="ICEF", unsure="r"),
    "perl": _Family("perl", inline="eE", arg="I", unsure="Mm"),
    "php": _Family("php", inline="r", arg="dc", file="f", unsure="S"),
}
_NODE_LIKE = re.compile(r"(?:^|/)(?:node|nodejs)\d*(?:\.\d+)*$")
_DENO_LIKE = re.compile(r"(?:^|/)(?:deno|bun)$")
_INTERP_OTHER = re.compile(r"(?:^|/)(?:node|nodejs|deno|bun|ruby|perl|php)\d*(?:\.\d+)*$")
_SH_EXTRA = re.compile(r"(?:^|/)(?:fish|csh|tcsh)$")


def _family_of(word: str) -> Optional[str]:
    base = word.rsplit("/", 1)[-1]
    if _PY_INTERP.search(word):
        return "python"
    if _SH_INTERP.search(word) or _SH_EXTRA.search(word):
        return "sh"
    if _NODE_LIKE.search(word) or _DENO_LIKE.search(word):
        return "node"
    if re.fullmatch(r"ruby\d*(?:\.\d+)*", base):
        return "ruby"
    if re.fullmatch(r"perl\d*(?:\.\d+)*", base):
        return "perl"
    if re.fullmatch(r"php\d*(?:\.\d+)*", base):
        return "php"
    return None


def _interp_args(family: str, rest: List[str], word: str = "") -> Tuple[str, str]:
    """Read an interpreter's arguments. Returns (kind, value): ``("file", operand)``,
    ``("inline", "")`` for a program given as text, ``("stdin", "")`` for one read from
    stdin, or ``("unsure", reason)`` for options that load code the kit does not
    follow."""
    fam = _FAMILIES[family]
    j = 0
    if _DENO_LIKE.search(word):
        # `deno run x.ts`, `bun run x.js`: the subcommand is not the script
        while j < len(rest) and rest[j].startswith("-"):
            j += 1
        if j < len(rest) and rest[j] == "run":
            rest = rest[:j] + rest[j + 1:]
        elif j < len(rest) and rest[j] in ("eval", "repl"):
            return "inline", ""
        elif j < len(rest) and rest[j] in ("test", "task", "install", "x", "upgrade", "add",
                                            "remove", "init", "create", "compile", "bundle",
                                            "check", "fmt", "lint", "serve", "repl"):
            return "unsure", f"a {rest[j]} subcommand"
        j = 0
    while j < len(rest):
        w = rest[j]
        if w == "--":
            j += 1
            break
        if w == "-" or not w.startswith(("-", "+")) or (w[0] == "+" and not fam.plus_opts):
            break
        if w.startswith("--"):
            name = w.split("=", 1)[0]
            if name in fam.long_inline:
                return "inline", ""
            if name in fam.long_unsure:
                return "unsure", f"the {name} option preloads code"
            if name in fam.long_arg and "=" not in w:
                j += 2
            else:
                j += 1
            continue
        step = 1
        for k, ch in enumerate(w[1:], 1):
            attached = k + 1 < len(w)
            if ch in fam.inline:
                return "inline", ""
            if ch in fam.unsure:
                return "unsure", f"the -{ch} option preloads code"
            if ch in fam.stdin and w[0] == "-":
                return "stdin", ""
            if ch in fam.file:
                if attached:
                    return "file", w[k + 1:]
                return ("file", rest[j + 1]) if j + 1 < len(rest) else ("stdin", "")
            if ch in fam.arg:
                step = 1 if attached else 2
                break
        j += step
    if j >= len(rest) or rest[j] == "-":
        return "stdin", ""
    return "file", rest[j]


def _operand_of(rest: List[str], python: bool) -> Optional[str]:
    """The script operand of a Python or shell command line (kept for callers that
    only need the operand); None for inline text, stdin, or no operand."""
    kind, value = _interp_args("python" if python else "sh", rest)
    return value if kind == "file" else None


def _interpreter_operands(entry: dict, interp: "re.Pattern[str]", root: Path,
                          plugin_root: Optional[Path]) -> List[str]:
    """Project-relative files passed as the SCRIPT operand of an interpreter
    token (``python3 -u x``, ``bash -e x``). Only the script operand: a data file
    passed later on the line is not code. Options are read per interpreter family."""
    words = _entry_words(entry, root, plugin_root)
    toks = [w for w, _ in words]
    out: List[str] = []
    for i, tok in enumerate(toks):
        if not interp.search(tok):
            continue
        family = _family_of(tok)
        if family is None:
            continue
        # arguments run to the end of the command: ops are not in `toks`, so stop at
        # the next interpreter-free boundary by taking the rest of the words
        kind, operand = _interp_args(family, toks[i + 1:], tok)
        if kind != "file":
            continue
        tok_j = operand
        cwd_rel = words[toks.index(operand, i + 1)][1] if operand in toks[i + 1:] else ""
        p = _var_path(tok_j, root, plugin_root)
        if p is None:
            if "CLAUDE_PROJECT_DIR" in tok_j or "CLAUDE_PLUGIN_ROOT" in tok_j:
                continue
            p = Path(os.path.expandvars(os.path.expanduser(tok_j)))
            if not p.is_absolute():
                if cwd_rel is None:
                    continue                  # named by not_checked_handlers
                p = root / _join(cwd_rel, tok_j)
        rel = _rel_or_none(p, root)
        if rel is not None and not rel.startswith(".."):
            out.append(rel)
    return out


COMMAND_TYPES = ("command", None)   # an entry with no `type` is a command entry


def not_checked_handlers(hooks_block: dict, label: str, root: Path,
                         plugin_root: Optional[Path] = None) -> List[str]:
    """Registrations whose behaviour the kit cannot vouch for: non-command
    handler types, and command entries that run no file inside the project."""
    out: List[str] = []
    for event, entry in _entries(hooks_block):
        htype = entry.get("type")
        if htype not in COMMAND_TYPES:
            target = entry.get("url") or entry.get("server") or entry.get("tool") or ""
            out.append(f"[{event}] {htype} handler in {label}"
                       + (f" ({target})" if target else "")
                       + ": its definition is pinned; what it calls is outside this kit")
            continue
        rels, ext, unplaced = script_refs_full(entry, root, plugin_root)
        for u in unplaced:
            out.append(f"[{event}] command in {label} runs {u[:80]} after a `cd` this kit "
                       "cannot place inside the project (a variable, -P, outside the "
                       "project): NOT CHECKED, not hashed")
        if not rels and not ext and not unplaced and not is_kit_entry(entry):
            cmd = " ".join(_texts(entry)).strip()
            out.append(f"[{event}] command in {label} names no file this kit can hash: "
                       f"{cmd[:120]}")
    return out


class Registrations:
    """Every hook block the kit reads, from any origin, resolved the same way."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.scripts: Dict[str, Set[str]] = {}
        self.external: Set[Tuple[str, str]] = set()
        self.python: Set[str] = set()
        self.shell: Set[str] = set()
        self.not_checked: List[str] = []
        self.texts: List[Tuple[str, str]] = []
        self.kit_registrations = 0

    def add_block(self, block: dict, label: str, plugin_root: Optional[Path] = None,
                  event_prefix: str = "") -> None:
        root = self.root
        self.not_checked += not_checked_handlers(block, label, root, plugin_root)
        for event, entry in _entries(block):
            if entry.get("type") not in COMMAND_TYPES:
                continue
            if is_kit_entry(entry):
                self.kit_registrations += 1
            if plugin_root is None:
                self.texts.append((event_prefix + event, "\n".join(_texts(entry))))
            rels, ext = script_refs(entry, root, plugin_root)
            for rel in rels:
                self.scripts.setdefault(rel, set()).add(event_prefix + event)
            self.external.update((event_prefix + event, e) for e in ext)
            self.python.update(_interpreter_operands(entry, _PY_INTERP, root, plugin_root))
            self.shell.update(_interpreter_operands(entry, _SH_INTERP, root, plugin_root))
            for rel in rels:
                kind = _script_kind(root / rel)
                if kind == "python":
                    self.python.add(rel)
                elif kind == "shell":
                    self.shell.add(rel)


def _script_kind(path: Path) -> Optional[str]:
    """'python' or 'shell' from the suffix, else from the shebang."""
    if path.suffix in (".py", ".pyw"):
        return "python"
    if path.suffix in _SHELL_SUFFIXES:
        return "shell"
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            first = f.readline(256)
    except OSError as e:
        raise NotEvaluable(f"cannot read {path} to see what runs it: {e}") from e
    if not first.startswith(b"#!"):
        return None
    if b"python" in first:
        return "python"
    if re.search(rb"(?:/|\s)(?:ba|z|da|k)?sh\b", first):
        return "shell"
    return None


# ── plugins: every place a repo-local plugin can declare hooks ──────────────

def _read_json(path: Path, root: Path, what: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise NotEvaluable(f"{what} unreadable: {_rel_or_none(path, root) or path}: {e}") from e


def _hooks_of_registration(data: object, rel: str) -> dict:
    if not isinstance(data, dict):
        raise NotEvaluable(f"plugin hooks file is not a JSON object: {rel}")
    hooks = data.get("hooks")
    if hooks is None:
        return {}
    if not isinstance(hooks, dict):
        raise NotEvaluable(f"`hooks` is not an object in {rel}")
    return hooks


def plugin_inventory(root: Path, regs: Registrations) -> List[str]:
    """Feed every repo-local plugin hook block into ``regs``; return the
    registration files to hash. Covers ``hooks/hooks.json`` at any depth (nested
    marketplace layouts included) and each ``.claude-plugin/plugin.json``, whose
    ``hooks`` field may be a path, a list of paths, or an inline object. A file
    that cannot be read or parsed raises NotEvaluable, exactly as a broken
    settings file does: skipping it would hide every script it registers."""
    plugdir = root / PLUGINS_DIR_REL
    if not plugdir.is_dir():
        return []
    files: List[str] = []
    seen: Set[Path] = set()

    def rel(p: Path) -> str:
        return _rel_or_none(p, root) or str(p)

    def feed(path: Path, plugin_root: Path, data: object, label: str) -> None:
        block = _hooks_of_registration(data, label)
        regs.add_block(block, f"plugin {label}", plugin_root,
                       event_prefix=f"plugin:{plugin_root.name}:")

    for dirpath, dirnames, _files in os.walk(plugdir):
        for d in dirnames:
            if (Path(dirpath) / d).is_symlink():
                regs.not_checked.append(f"{rel(Path(dirpath) / d)} is a symlink to a directory: "
                                        "plugin hooks behind it are not read or hashed")

    for hj in sorted(plugdir.rglob("hooks.json")):
        if hj.parent.name != "hooks" or not hj.is_file():
            continue
        files.append(rel(hj))
        seen.add(hj.resolve())
        feed(hj, hj.parent.parent, _read_json(hj, root, "plugin hooks file"), rel(hj))

    for pj in sorted(plugdir.rglob("plugin.json")):
        if pj.parent.name != ".claude-plugin" or not pj.is_file():
            continue
        plugin_root = pj.parent.parent
        files.append(rel(pj))
        data = _read_json(pj, root, "plugin manifest")
        if not isinstance(data, dict):
            raise NotEvaluable(f"plugin manifest is not a JSON object: {rel(pj)}")
        h = data.get("hooks")
        for item in (h if isinstance(h, list) else ([] if h is None else [h])):
            if isinstance(item, str):
                ref = re.sub(r"^\$\{?CLAUDE_PLUGIN_ROOT\}?/", "", item)
                target = Path(os.path.normpath(plugin_root / ref))
                trel = _rel_or_none(target, root)
                if trel is None:
                    regs.not_checked.append(f"{rel(pj)} points its hooks at {item}, "
                                            "outside the project")
                    continue
                if target.resolve() in seen:
                    continue
                seen.add(target.resolve())
                files.append(trel)          # hashed; a missing one is a finding
                if target.is_file():
                    feed(target, plugin_root, _read_json(target, root, "plugin hooks file"), trel)
            elif isinstance(item, dict):
                inline = item if isinstance(item.get("hooks"), dict) else {"hooks": item}
                feed(pj, plugin_root, inline, f"{rel(pj)} (inline hooks)")
            else:
                raise NotEvaluable(f"`hooks` in {rel(pj)} is neither a path nor an object")
        if data.get("mcpServers"):
            regs.not_checked.append(f"MCP servers declared in {rel(pj)} (mcpServers): "
                                    "they run commands this kit does not hash")

    for mj in sorted(plugdir.rglob("marketplace.json")):
        if mj.parent.name != ".claude-plugin" or not mj.is_file():
            continue
        try:
            data = json.loads(mj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            regs.not_checked.append(f"{rel(mj)} cannot be parsed; hooks it declares "
                                    "for its plugins are not checked")
            continue
        plugins = data.get("plugins") if isinstance(data, dict) else None
        if isinstance(plugins, list) and any(isinstance(p, dict) and "hooks" in p for p in plugins):
            regs.not_checked.append(f"{rel(mj)} declares hooks inside marketplace "
                                    "entries: not followed or hashed")

    for mcp in sorted(plugdir.rglob(".mcp.json")):
        if mcp.is_file():
            regs.not_checked.append(f"MCP server config {rel(mcp)}: its servers run "
                                    "commands this kit does not hash")
    return files


def plugin_registration_files(root: Path) -> List[str]:
    """The plugin registration files the baseline hashes (see plugin_inventory)."""
    return plugin_inventory(root, Registrations(root))


# ── frontmatter hooks: named, never parsed ──────────────────────────────────

_FRONTMATTER_GLOBS = (".claude/skills/**/SKILL.md", ".claude/agents/**/*.md",
                      ".claude/plugins/**/skills/**/SKILL.md",
                      ".claude/plugins/**/agents/**/*.md")
_FM_HOOKS_KEY = re.compile(r"""(?m)(?:^|[{,])[ \t]*["']?hooks["']?[ \t]*:""")


def frontmatter_hook_files(root: Path) -> List[str]:
    """Skill and subagent files whose YAML frontmatter declares ``hooks``.
    Named, not parsed: they are outside the kit's coverage. The whole
    frontmatter is scanned, a byte-order mark is ignored, and quoted and flow
    style keys count; a false positive only adds a NOT CHECKED line."""
    found: set = set()
    for pattern in _FRONTMATTER_GLOBS:
        for p in root.glob(pattern):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                found.add(p.relative_to(root).as_posix() + " (unreadable)")
                continue
            text = text.lstrip("\ufeff").replace("\r\n", "\n")
            end = text.find("\n---", 3)
            if text.startswith("---") and end > 0 and _FM_HOOKS_KEY.search(text[3:end]):
                found.add(p.relative_to(root).as_posix())
    return sorted(found)


def on_disk_hook_scripts(root: Path) -> List[str]:
    """Hook-shaped scripts under .claude/hooks/ and any plugin ``hooks`` dir."""
    bases = [root / HOOKS_DIR_REL]
    plugdir = root / PLUGINS_DIR_REL
    if plugdir.is_dir():
        bases += sorted(p for p in plugdir.rglob("hooks") if p.is_dir())
    found: List[str] = []
    for base in bases:
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.suffix not in _HOOK_SUFFIXES:
                continue
            if _SKIP_DIRS & set(p.relative_to(base).parts[:-1]):
                continue
            rel = p.relative_to(root).as_posix()
            if rel not in found:
                found.append(rel)
    return found


# ── Python: resolve imports the way the interpreter does ────────────────────

def imported_module_names(src: str) -> set:
    """Top-level module names a source file imports, via the AST (empty for a
    file that does not parse; the walk below treats that as NOT EVALUABLE)."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return set()
    return _imports(tree)[0]


#: Names that load or run code by name, path or text rather than by an ``import``
#: statement. Any REFERENCE to one (a call, an alias, an assignment) marks the file.
_DYNAMIC_NAMES = frozenset((
    "__import__", "import_module", "addsitedir", "spec_from_file_location",
    "spec_from_loader", "module_from_spec", "exec_module", "load_module",
    "SourceFileLoader", "SourcelessFileLoader", "ExtensionFileLoader",
    "run_module", "run_path", "load_source", "load_compiled", "load_dynamic"))
_READ_ATTRS = frozenset(("read", "read_text", "read_bytes", "readlines"))


def _reads_a_file(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if (isinstance(f, ast.Name) and f.id == "open") or (
                    isinstance(f, ast.Attribute) and f.attr in _READ_ATTRS | {"open"}):
                return True
    return False


#: ``sys`` members that steer what an ``import`` loads.
_SYS_WATCH = frozenset(("path", "meta_path", "path_hooks", "path_importer_cache", "modules",
                        "__dict__"))
#: Builtins that only READ a list handed to them.
_READ_CALLS = frozenset(("len", "print", "sorted", "list", "tuple", "set", "frozenset", "repr",
                         "str", "iter", "enumerate", "reversed", "sum", "any", "all", "min",
                         "max", "bool", "id", "type"))
_READ_METHODS = frozenset(("index", "count", "copy", "__len__", "__contains__", "__getitem__",
                          "get", "keys", "values", "items"))


def _plain_read(node: ast.AST, parent: Optional[ast.AST]) -> bool:
    """Whether ``node`` (a reference to ``sys.path`` or the like) is only READ here: it
    cannot change the list. Anything else (a store or delete, a subscript store, a
    mutating method, an alias, an argument to a function that may mutate it) is not."""
    if isinstance(parent, ast.Subscript):
        return parent.value is node and isinstance(parent.ctx, ast.Load)
    if isinstance(parent, (ast.Compare, ast.BinOp, ast.FormattedValue, ast.Expr)):
        return True
    if isinstance(parent, (ast.For, ast.comprehension)):
        return getattr(parent, "iter", None) is node
    if isinstance(parent, ast.Call):
        return (node in parent.args and isinstance(parent.func, ast.Name)
                and parent.func.id in _READ_CALLS)
    if isinstance(parent, ast.Attribute):
        return parent.attr in _READ_METHODS
    return False


def _imports(tree: ast.AST, folded: frozenset = frozenset()) -> Tuple[Set[str], bool]:
    """(top-level imported names, whether the file changes the import machinery or
    loads code dynamically). The AST, not a regex: it sees imports inside functions
    and ``try:`` blocks and cannot be fooled by one inside a string.

    Dynamic means: ``importlib`` / ``runpy`` / ``imp`` / ``builtins.__import__``
    loaders (also imported by name or under an alias, or merely referenced), ANY
    reference to ``sys.path``, ``sys.meta_path``, ``sys.path_hooks``,
    ``sys.path_importer_cache``, ``sys.modules`` or ``sys.__dict__`` (also via
    ``import sys as s`` or ``from sys import path``) other than a plain read, a
    ``sys`` module object that is passed or aliased rather than attributed
    (``getattr(sys, ...)``, ``vars(sys)``, ``s = sys``), and ``exec`` / ``eval`` of
    anything that is not a string literal. Not seen: ``getattr(mod,
    "import_module")``, code reached through ``subprocess``, and names assembled at
    run time. ``folded`` holds the ids of ``sys.path`` nodes whose ``insert``/``append``
    argument was worked out from the file alone (``_sys_path_dirs``); those are followed by
    the caller, so they do not make the file dynamic."""
    names: Set[str] = set()
    dynamic = False
    parent: Dict[int, ast.AST] = {}
    sys_names: Set[str] = {"sys"}
    watched: Set[str] = set()            # names bound to sys.path & co by `from sys import`
    imports_sys = False
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "sys":
                    sys_names.add(a.asname or "sys")
                    imports_sys = True
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "sys":
            imports_sys = True
            for a in node.names:
                if a.name in _SYS_WATCH:
                    watched.add(a.asname or a.name)
                elif a.name == "*":
                    dynamic = True       # `from sys import *` binds path, modules ... unseen
    for node in ast.walk(tree):
        par = parent.get(id(node))
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
            if node.module.split(".")[0] in ("importlib", "runpy", "builtins", "imp") and any(
                    a.name in _DYNAMIC_NAMES for a in node.names):
                dynamic = True
        elif isinstance(node, ast.Name):
            if node.id in _DYNAMIC_NAMES:
                dynamic = True
            if node.id in sys_names:
                if not (isinstance(par, ast.Attribute) and par.value is node):
                    dynamic = True       # the module object itself is passed or aliased
            elif node.id in watched:
                if not isinstance(node.ctx, ast.Load) or not _plain_read(node, par):
                    dynamic = True
        elif isinstance(node, ast.Attribute):
            if node.attr in _DYNAMIC_NAMES:
                dynamic = True
            if node.attr == "sys" or (node.attr == "__dict__" and isinstance(
                    node.value, ast.Name) and node.value.id in sys_names):
                dynamic = True           # `os.sys.path`, `sys.__dict__['path']`: sys by another name
            if (node.attr in _SYS_WATCH and isinstance(node.value, ast.Name)
                    and node.value.id in sys_names and id(node) not in folded):
                if not isinstance(node.ctx, ast.Load) or not _plain_read(node, par):
                    dynamic = True
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in ("globals", "locals") and len(sys_names) > 0 \
                    and imports_sys:
                dynamic = True           # `globals()['sys'].path`: sys fetched by name
            if isinstance(f, ast.Name) and f.id in ("exec", "eval"):
                if not (node.args and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)) or any(
                            _reads_a_file(a) for a in node.args):
                    dynamic = True
    return names, dynamic


# ── sys.path directories worked out from the file alone ──────────────────────
#
# The most common way a Python hook reaches a shared helper is
# ``sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "tools"))``, often
# through a module-level constant. Such an argument depends only on where the file is, so it
# can be evaluated without running anything: ``__file__``, ``Path(...)``, ``.parent``,
# ``.parents[N]``, ``.resolve()``, ``.absolute()``, ``/ "literal"``, ``.joinpath(...)``,
# ``str()``, ``os.fspath()``, ``os.path.dirname/abspath/realpath/normpath/join``, string
# literals as parts, and a module-level name assigned exactly once. Anything else (the
# environment, a function's return value, a cwd-relative literal) is not worked out, and the
# file stays NOT CHECKED as before.

_PATH_CALLS = frozenset(("Path", "PurePath", "PosixPath", "WindowsPath"))
_OS_PATH_FNS = frozenset(("dirname", "abspath", "realpath", "normpath", "join"))


def _module_constants(tree: ast.AST) -> Dict[str, List[ast.AST]]:
    """{name: [every value assigned to it]} for names bound ONLY by plain ``NAME = value``
    statements, anywhere in the file. A name bound any other way (a loop target, ``+=``,
    ``global``, an import, a parameter, ``with ... as``) is left out. Several assignments
    are several candidates: the caller searches every directory they could name."""
    values: Dict[str, List[ast.AST]] = {}
    other: Set[str] = set()
    plain: Set[int] = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)):
            values.setdefault(n.targets[0].id, []).append(n.value)
            plain.add(id(n.targets[0]))
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value:
            values.setdefault(n.target.id, []).append(n.value)
            plain.add(id(n.target))
    for n in ast.walk(tree):
        if isinstance(n, (ast.For, ast.AsyncFor, ast.While)):
            # a value assigned in a loop depends on how many times it ran
            for m in ast.walk(n):
                if isinstance(m, ast.Name) and isinstance(m.ctx, ast.Store):
                    other.add(m.id)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and id(n) not in plain:
            other.add(n.id)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            other.update(n.names)
        elif isinstance(n, ast.arg):
            other.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            other.update((a.asname or a.name).split(".")[0] for a in n.names)
    return {k: v for k, v in values.items() if k not in other}


def _is_os_path(f: ast.AST) -> Optional[str]:
    """``os.path.<fn>`` -> fn, for the functions the folder understands."""
    if (isinstance(f, ast.Attribute) and f.attr in _OS_PATH_FNS
            and isinstance(f.value, ast.Attribute) and f.value.attr == "path"
            and isinstance(f.value.value, ast.Name) and f.value.value.id == "os"):
        return f.attr
    return None


_FOLD_MAX = 16          # candidate values per expression; more is not worked out


def _fold(node: ast.AST, here: Path, consts: Dict[str, List[ast.AST]], depth: int = 0,
          bound: Optional[Dict[str, Optional[list]]] = None):
    """Every value ``node`` can take, as [('path', Path) | ('str', literal)], or None when
    any of them cannot be worked out from the file alone. ``bound`` gives a name's value while
    one of its own assignments is folded: ``base = join(base, "lib")`` reads the value ``base``
    had before it, as the code runs in order."""
    if depth > 12:
        return None
    bound = bound or {}
    rec = lambda n: _fold(n, here, consts, depth + 1, bound)  # noqa: E731

    def each(vals, fn):
        out = []
        for v in vals:
            r = fn(v)
            if r is None:
                return None
            out.append(r)
        return out if len(out) <= _FOLD_MAX else None

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("str", node.value)]
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return [("path", here)]
        if node.id in bound:
            return bound[node.id]
        if node.id in consts:
            got: list = []
            prev: Optional[list] = None
            for v in consts[node.id]:
                r = _fold(v, here, consts, depth + 1, dict(bound, **{node.id: prev}))
                if r is None:
                    return None
                got.extend(r)
                prev = r
            return got if len(got) <= _FOLD_MAX else None
        return None
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        vals = rec(node.value)
        return vals and each(vals, lambda v: ("path", v[1].parent) if v[0] == "path" else None)
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"):
        k = node.slice.value if isinstance(node.slice, ast.Constant) else None
        vals = rec(node.value.value)
        if not isinstance(k, int) or k < 0:
            return None
        return vals and each(vals, lambda v: ("path", v[1].parents[k])
                             if v[0] == "path" and k < len(v[1].parents) else None)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        a, b = rec(node.left), rec(node.right)
        if not a or not b or len(a) * len(b) > _FOLD_MAX:
            return None
        if any(x[0] != "path" for x in a):
            return None
        return [("path", x[1] / y[1]) for x in a for y in b]
    if isinstance(node, ast.Call) and not node.keywords:
        f, args = node.func, node.args
        if isinstance(f, ast.Name) and f.id in _PATH_CALLS and len(args) == 1:
            vals = rec(args[0])
            return vals and each(vals, lambda v: ("path", Path(v[1]))
                                 if v[0] == "path" or os.path.isabs(v[1]) else None)
        if ((isinstance(f, ast.Name) and f.id == "str")
                or (isinstance(f, ast.Attribute) and f.attr == "fspath"
                    and isinstance(f.value, ast.Name) and f.value.id == "os")) and len(args) == 1:
            return rec(args[0])
        if isinstance(f, ast.Attribute) and f.attr in ("resolve", "absolute") and not args:
            vals = rec(f.value)
            return vals and each(vals, lambda v: ("path", v[1].resolve() if f.attr == "resolve"
                                                  else v[1]) if v[0] == "path" else None)
        if isinstance(f, ast.Attribute) and f.attr == "joinpath":
            vals = rec(f.value)
            parts = [rec(a) for a in args]
            if not vals or not all(p and len(p) == 1 for p in parts):
                return None
            return each(vals, lambda v: ("path", v[1].joinpath(*(p[0][1] for p in parts)))
                        if v[0] == "path" else None)
        fn = _is_os_path(f)
        if fn and args:
            first = rec(args[0])
            rest = [rec(a) for a in args[1:]]
            if not first or not all(r and len(r) == 1 for r in rest):
                return None
            tail = [r[0][1] for r in rest]
            if fn == "join":
                return each(first, lambda v: ("path", Path(os.path.join(str(v[1]), *map(str, tail))))
                            if v[0] == "path" else None)
            if tail:
                return None
            op = {"dirname": os.path.dirname, "abspath": os.path.normpath,
                  "normpath": os.path.normpath, "realpath": os.path.realpath}[fn]
            return each(first, lambda v: ("path", Path(op(str(v[1])))) if v[0] == "path" else None)
        return None
    return None


def _sys_path_dirs(tree: ast.AST, here: Path) -> Tuple[List[Path], frozenset]:
    """(directories added by ``sys.path.insert``/``append`` that could be worked out, ids of
    the ``sys.path`` nodes those calls use). Only ``sys`` imported as ``sys`` is read."""
    consts = _module_constants(tree)
    dirs: List[Path] = []
    done: Set[int] = set()
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("insert", "append") and not n.keywords):
            continue
        target = n.func.value
        if not (isinstance(target, ast.Attribute) and target.attr == "path"
                and isinstance(target.value, ast.Name) and target.value.id == "sys"):
            continue
        arg = n.args[1] if n.func.attr == "insert" and len(n.args) == 2 else (
            n.args[0] if n.func.attr == "append" and len(n.args) == 1 else None)
        vals = _fold(arg, here, consts) if arg is not None else None
        if vals and all(v[0] == "path" for v in vals):
            dirs.extend(Path(os.path.normpath(v[1])) for v in vals)
            done.add(id(target))
    return dirs, frozenset(done)


def _dotted_imports(tree: ast.AST) -> Set[str]:
    """Absolute dotted names a file imports: ``import a.b`` -> a.b; ``from a.b import c`` ->
    a.b and a.b.c (c may be a submodule)."""
    out: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            out.add(n.module)
            out.update(f"{n.module}.{a.name}" for a in n.names if a.name != "*")
    return out


def _relative_files(path: Path, tree: ast.AST) -> List[Path]:
    """Files a module's relative imports run: ``from . import x`` / ``from ..a import b``,
    resolved against the importing file's own package directory."""
    files: List[Path] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.ImportFrom) and n.level > 0):
            continue
        base = path.parent
        for _ in range(n.level - 1):
            base = base.parent
        targets = [n.module] if n.module else []
        targets += [f"{n.module}.{a.name}" if n.module else a.name
                    for a in n.names if a.name != "*"]
        for t in targets:
            files.extend(_dotted_files(base, t) or [])
    return files


def _dotted_files(d: Path, dotted: str) -> Optional[List[Path]]:
    """The files Python runs for ``import <dotted>`` with ``d`` on sys.path: each package's
    ``__init__`` on the way down and the module (or package ``__init__``) named last. None
    when the top-level name is not in ``d``. A trailing name that is not a module (an
    attribute, as in ``from a import x``) adds nothing."""
    parts = dotted.split(".")
    files: List[Path] = []
    cur = d
    for i, part in enumerate(parts):
        found = find_module(cur, part)
        if found is None:
            return None if i == 0 else files
        kind, fp = found
        if kind == "module":
            files.append(fp)
            return files
        if kind == "package":
            inits = _module_candidates(fp, "__init__")
            files.append(inits[0])
        cur = fp
    return files


_STDLIB: Optional[Set[str]] = None


def _stdlib_names() -> Set[str]:
    global _STDLIB
    if _STDLIB is None:
        names = set(getattr(sys, "stdlib_module_names", ()) or ())
        names |= set(sys.builtin_module_names)
        if not getattr(sys, "stdlib_module_names", None):      # Python 3.9
            paths = sysconfig.get_paths()
            for d in {paths.get("stdlib"), paths.get("platstdlib")}:
                for base in (d, os.path.join(d, "lib-dynload") if d else None):
                    if base and os.path.isdir(base):
                        for n in os.listdir(base):
                            names.add(n.split(".")[0])
        _STDLIB = names
    return _STDLIB


def _listdir(d: Path) -> List[str]:
    try:
        return sorted(os.listdir(d))
    except FileNotFoundError:
        return []
    except OSError as e:
        raise NotEvaluable(f"cannot list {d} to resolve imports: {e}") from e


def _module_candidates(d: Path, stem: str) -> List[Path]:
    """Files the path finder would try for ``stem`` in ``d``, in its order:
    extension modules, then source, then sourceless bytecode."""
    names = _listdir(d)
    ext = [n for n in names if n.startswith(stem + ".") and n.endswith((".so", ".pyd"))]
    order = ext + [n for n in (stem + ".py", stem + ".pyw", stem + ".pyc") if n in names]
    return [d / n for n in order if (d / n).is_file()]


def find_module(d: Path, mod: str) -> Optional[Tuple[str, Path]]:
    """What the path finder for directory ``d`` loads for top-level ``mod``:
    ('package', dir), ('module', file) or ('namespace', dir), or None. A regular
    package beats a module of the same name, and both beat a namespace portion."""
    pkg = d / mod
    if pkg.is_dir() and _module_candidates(pkg, "__init__"):
        return "package", pkg
    cands = _module_candidates(d, mod)
    if cands:
        return "module", cands[0]
    if pkg.is_dir():
        return "namespace", pkg
    return None


def _package_files(pkg: Path, root: Optional[Path] = None
                   ) -> Tuple[List[Path], List[str]]:
    """(files under ``pkg``, not-checked notes). Directory symlinks are FOLLOWED,
    because the interpreter imports through them: a subpackage reached by a link
    is code that runs. Files keep their lexical path (link identity). A link that
    loops back onto one of its own ancestors is not re-entered, and a link whose
    target lies outside ``root`` is named NOT CHECKED rather than skipped."""
    out: List[Path] = []
    notes: List[str] = []
    rroot = root.resolve() if root is not None else None

    def walk(d: Path, chain: Tuple[Path, ...]) -> None:
        for name in _listdir(d):
            p = d / name
            if name in _SKIP_DIRS and p.is_dir():
                continue
            if p.is_dir():
                real = p.resolve()
                if real in chain:
                    notes.append(f"{p} is a symlink loop onto {real}: not re-entered")
                    continue
                if p.is_symlink() and rroot is not None and _rel_or_none(real, rroot) is None:
                    notes.append(f"{p} is a symlink to {real}, outside the project: "
                                 "the package files behind it are not followed")
                    continue
                walk(p, chain + (real,))
            elif p.is_file():
                out.append(p)

    walk(pkg, (pkg.resolve(),))
    return out, notes


_WALK_SKIP = frozenset((".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
                        ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages"))


def _project_module_files(root: Path, mods: Sequence[str], limit: int = 20000
                          ) -> Dict[str, List[str]]:
    """{module name: [project-relative files that would be that module]} for the names in
    ``mods`` (``name.py``, ``name/__init__.py``) anywhere in the project, skipping VCS
    and virtualenv directories. Bounded: after ``limit`` entries the walk stops."""
    want = set(mods)
    out: Dict[str, List[str]] = {}
    if not want:
        return out
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _WALK_SKIP)
        base = Path(dirpath)
        for fn in sorted(filenames):
            seen += 1
            stem, ext = os.path.splitext(fn)
            if ext in (".py", ".pyc", ".so") and stem.split(".")[0] in want:
                rel = _rel_or_none(base / fn, root)
                if rel:
                    out.setdefault(stem.split(".")[0], []).append(rel)
            elif fn == "__init__.py" and base.name in want:
                rel = _rel_or_none(base / fn, root)
                if rel:
                    out.setdefault(base.name, []).append(rel)
        if seen > limit:
            break
    return out


_STARTS_PROCESS = re.compile(r"\bsubprocess\b|\bos\.(?:system|popen|exec[lv]\w*|spawn[lv]\w*)\b")


def text_of(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def stdlib_shadows(root: Path, entries: Iterable[str]) -> Dict[str, List[str]]:
    """{rel file: [hook stems]}: files beside a Python hook named like a standard-library
    module. `sys.path[0]` is the hook's directory, and a stdlib module's own imports search it
    first, so `import json` can run a planted `decoder.py` the hook never names. Hashed whether
    or not anything imports them."""
    stdlib = _stdlib_names()
    out: Dict[str, Set[str]] = {}
    for rel in entries:
        try:
            d = (root / rel).resolve().parent
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for n in names:
            stem, ext = os.path.splitext(n)
            f = d / n
            if ((ext in (".py", ".pyc", ".so") and stem.split(".")[0] in stdlib and f.is_file())
                    or (not ext and n in stdlib and (f / "__init__.py").is_file())):
                f = f / "__init__.py" if not ext else f
                frel = _rel_or_none(f, root) or _rel_or_none(f, root.resolve())
                if frel and f != (root / rel).resolve():
                    out.setdefault(frel, set()).add(Path(rel).stem)
    return {k: sorted(v) for k, v in out.items()}


def venv_startup_files(root: Path, commands: Iterable[str]) -> List[str]:
    """Project files a project virtualenv runs at every interpreter start: `.pth` files and
    `sitecustomize.py` in its site-packages. Only for a venv a hook command names. Named, not
    hashed: the baseline is committed, and these differ on every machine (an editable install's
    `.pth` holds an absolute path), so a hash would read as drift everywhere else."""
    out: Set[str] = set()
    for venv in sorted({m.group(1) for c in commands
                        for m in re.finditer(r"(?:^|[\s/\"'=}])(\.?venv|env)/(?:bin|Scripts)/py", c)}):
        for site in (root / venv).glob("lib*/python*/site-packages"):
            for f in list(site.glob("*.pth")) + list(site.glob("sitecustomize.py")):
                frel = _rel_or_none(f, root)
                if frel:
                    out.add(frel)
    return sorted(out)


def import_walk(root: Path, entries: Iterable[str]
                ) -> Tuple[Dict[str, List[str]], List[str], List[str]]:
    """({rel file: [origin hook stems]}, not-checked notes, rel .py sources whose
    bytecode caches matter) for Python entry points.

    Resolution follows the interpreter: ``sys.path[0]`` is the entry point's
    RESOLVED directory, and each top-level import is looked up there in the path
    finder's order. Whatever wins is hashed (a stdlib name shadowed by a sibling
    package or a ``.pyc`` included). A file that cannot be read or parsed raises
    NotEvaluable: its imports cannot be followed, and silence would read as
    clean."""
    rroot = root.resolve()
    out: Dict[str, Set[str]] = {}
    notes: List[str] = []
    sources: Set[str] = set()
    stdlib = _stdlib_names()
    # (file, rel, origin hook, the entry point's directory, its lexical form, directories
    # added to sys.path along the way and worked out from the files that added them)
    frontier: List[Tuple[Path, str, str, Path, Path, Tuple[Path, ...]]] = []

    def name_of(f: Path, search: Path, base: Path) -> Optional[str]:
        shown = base / f.relative_to(search)
        return _rel_or_none(shown, root) or _rel_or_none(f, rroot)

    for rel in sorted(set(entries)):
        p = root / rel
        if not p.is_file():
            continue
        search = p.resolve().parent
        base = p.parent if p.parent.resolve() == search else search
        if _rel_or_none(base, root) is None and _rel_or_none(search, rroot) is None:
            notes.append(f"{rel} resolves to {p.resolve()}, outside the project: the "
                         "modules it imports are not followed")
            continue
        frontier.append((p, rel, p.stem, search, base, ()))

    # Each file is read, parsed and resolved ONCE per (search path, added directories); the
    # walk then only carries origins. A shared helper reached from sixty hooks is analysed
    # once, and its notes are written once.
    cache: Dict[Tuple[str, str, str, Tuple[Path, ...]], Tuple] = {}
    note_set: Set[str] = set(notes)

    def note(text: str) -> None:
        if text not in note_set:
            note_set.add(text)
            notes.append(text)

    def analyse(path: Path, rel: str, search: Path, base: Path, extras: Tuple[Path, ...]):
        """(extras after this file, [(file for the frontier, rel, suffix)], [notes])."""
        try:
            size = path.stat().st_size
            if size > PY_PARSE_MAX_BYTES:
                raise NotEvaluable(
                    f"{rel} is {size} bytes, over the {PY_PARSE_MAX_BYTES} byte limit for "
                    "following its imports (hook code is small; a huge file is not parsed): "
                    "NOT EVALUABLE")
            src = path.read_bytes()
        except OSError as e:
            # Skipping it would hide its whole import graph.
            raise NotEvaluable(f"cannot read {rel} to follow its imports: {e}") from e
        try:
            tree = ast.parse(src, filename=rel)
        except (SyntaxError, ValueError) as e:
            raise NotEvaluable(
                f"cannot parse {rel} with Python {_py_version()} ({e.__class__.__name__}: "
                f"{e}), so the modules it imports cannot be followed. Run the kit with "
                "the interpreter your hooks use") from e
        fnotes: List[str] = []
        added, folded = _sys_path_dirs(tree, path.absolute())
        for d in added:
            if _rel_or_none(d, root) is None and _rel_or_none(d.resolve(), rroot) is None:
                fnotes.append(f"{rel} adds {d} to sys.path, outside the project: modules "
                              "found there are not followed")
            elif d not in extras:
                extras = extras + (d,)
        names, dynamic = _imports(tree, folded)
        dotted = _dotted_imports(tree) if extras else set()
        if dynamic:
            fnotes.append(f"{rel} changes sys.path or loads code dynamically (importlib, "
                          "runpy, __import__, exec/eval of non-literal text): modules loaded "
                          "that way are not followed")
        if _STARTS_PROCESS.search(text_of(path)):
            fnotes.append(f"{rel} starts other programs (subprocess, os.system, ...): a script "
                          "started that way is not followed or hashed")
        kids: List[Tuple[Path, str, str]] = []
        unresolved = []
        me = path.resolve()
        for mod in sorted(names):
            # every directory added to sys.path is searched too, and every match is hashed,
            # so an insert behind a condition still has its target covered
            in_extras = False
            for d in extras:
                hit = find_module(d, mod)
                if hit is None or (hit[0] == "namespace" and mod in stdlib):
                    continue
                in_extras = True
                # exactly what Python runs for each dotted import under this name
                hfiles = []
                for dn in sorted(x for x in dotted if x == mod or x.startswith(mod + ".")):
                    hfiles.extend(_dotted_files(d, dn) or [])
                for f in dict.fromkeys(hfiles):
                    frel = _rel_or_none(f, root) or _rel_or_none(f.resolve(), rroot)
                    if frel is not None and f.resolve() != me:
                        kids.append((f, frel, f.suffix))
            found = find_module(search, mod)
            if found is None or (found[0] == "namespace" and mod in stdlib):
                if found is None and mod not in stdlib and not in_extras:
                    unresolved.append(mod)
                continue
            kind, fp = found
            if kind == "module":
                files = [fp]
            else:
                files, pnotes = _package_files(fp, root)
                fnotes.extend(pnotes)
            for f in files:
                frel = name_of(f, search, base)
                if frel is None or f.resolve() == me:
                    continue
                kids.append((base / f.relative_to(search), frel, f.suffix))
        if extras:
            # inside a package reached through sys.path, relative imports run too
            for f in dict.fromkeys(_relative_files(path, tree)):
                frel = _rel_or_none(f, root) or _rel_or_none(f.resolve(), rroot)
                if frel is not None and f.resolve() != me:
                    kids.append((f, frel, f.suffix))
        if dynamic:
            beside = {m for m in names if find_module(search, m) is not None
                      or any(find_module(d, m) is not None for d in extras)}
            shadows = _project_module_files(root, [m for m in sorted(names) if m not in beside])
            for mod, paths in sorted(shadows.items()):
                fnotes.append(f"{rel} imports {mod} and changes the import path, and the "
                              f"project holds {', '.join(paths[:3])}: a changed path could "
                              "load that instead of the module named (NOT CHECKED, not hashed)")
        if unresolved:
            fnotes.append(f"{rel} imports {', '.join(unresolved)}: not beside it, so "
                          "loaded from installed packages or a changed sys.path; not followed")
        return extras, kids, fnotes

    seen: Set[Tuple[str, str, Tuple[Path, ...]]] = set()
    while frontier:
        path, rel, origin, search, base, extras = frontier.pop()
        if (rel, origin, extras) in seen:
            continue
        seen.add((rel, origin, extras))
        key = (str(path), str(search), str(base), extras)
        if key not in cache:
            cache[key] = analyse(path, rel, search, base, extras)
        extras2, kids, fnotes = cache[key]
        for n in fnotes:
            note(n)
        for f, frel, suffix in kids:
            out.setdefault(frel, set()).add(origin)
            if suffix in (".py", ".pyw"):
                sources.add(frel)
                frontier.append((f, frel, origin, search, base, extras2))
            elif suffix in (".pyc", ".so", ".pyd"):
                note(f"{frel} is compiled code imported by {origin}: hashed, "
                     "but its own imports are not followed")
    return {k: sorted(v) for k, v in sorted(out.items())}, notes, sorted(sources)


def imported_by_registered(root: Path, registered: Sequence[str]) -> Dict[str, List[str]]:
    """{rel module: [origin hook stems]} for the Python files in ``registered``."""
    py = [r for r in registered if _script_kind(root / r) == "python"]
    return import_walk(root, py)[0]


# ── project files that a shell hook reaches ──────────────────────────────────
#
# The follower does NOT model the shell. Wrappers, option clusters, `cd`, subshells,
# functions, heredocs, CDPATH and `eval` each have endless spellings, and modelling
# them one at a time cannot converge. The rule is conservative and linear instead:
#
#   1. read the script as words (shell quoting honoured) AND as raw text, so heredoc
#      bodies, backticks, quoted strings, `-c` strings and option clusters are covered;
#   2. candidate directories = the project root, the script's own directory, and every
#      literal directory named after `cd`, `pushd`, `-C`, `--chdir`, `CDPATH=`, `PATH=`
#      anywhere in any reached script (and chains of them), inside the project;
#   3. every word or path-like substring that, joined to a candidate directory, is an
#      existing regular file in the project is HASHED, and followed with the same rule
#      when it is a shell script (a Python file goes to the import follower);
#   4. a construct whose effect on paths is not modelled is NAMED, once per script;
#   5. state is keyed by file path only, under a global work budget.
#
# Over-hashing (a data file a hook names that changes later reads as drift) is the
# price: fail toward drift, never toward silence.

EVENT_CALLED = "_called_by"
FOLLOW_MAX_FILES = 2000
FOLLOW_MAX_BYTES = 64 * 1024 * 1024
#: A Python file larger than this is not parsed: hook code is small, and parsing a huge file
#: is slow enough to outlast the session-start timeout in silence. It is NOT EVALUABLE.
PY_PARSE_MAX_BYTES = 1024 * 1024
FOLLOW_MAX_DIRS = 2000
FOLLOW_MAX_STATS = 3_000_000
_ROOT_MARK = "\x00"
# `$CLAUDE_PROJECT_DIR`, `${CLAUDE_PROJECT_DIR}` and the forms with a default (`${CLAUDE_PROJECT_DIR:-.}`)
_PROJECT_VAR = re.compile(_PDIR)
_PATHISH = re.compile(r"[\w.@+\-/\x00]+")
_CD_ARG = re.compile(
    r"""(?<![\w./-])(?P<cmd>cd|pushd)(?=[\s;&|)(<>]|$)[ \t]*(?:(?:-[A-Za-z]+|--)[ \t]+)*"""
    r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>[^\s;&|()<>"'`]+))?""")
_CHDIR_ARG = re.compile(
    r"""(?:(?<=\s)|^)(?:-C|--chdir)(?:[ \t]*=?[ \t]*)(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|"""
    r"""(?P<bare>[^\s;&|()<>"'`]+))""")
_PATH_ASSIGN = re.compile(r"""(?<![\w])(?P<var>CDPATH|PATH)=(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|"""
                          r"""(?P<bare>[^\s;&|()<>"'`]*))""")
_EVAL = re.compile(r"(?:^|[\s;&|(`{])eval(?=[\s;&|)]|$)")
_SOURCE_DYN = re.compile(r"""(?:^|[;&|({\s`])(?:source|\.)[ \t]+["']?[^\s;&|]*[$`]""")
_FUNC_DEF = re.compile(r"(?m)^[ \t]*(?:function[ \t]+[\w:.-]+|[\w:.-]+[ \t]*\([ \t]*\))")
_ALIAS = re.compile(r"(?:^|[;&|(\s`])alias(?=\s)")
_EXEC_REDIR = re.compile(r"(?:^|[;&|(\s`])exec[ \t]+(?:\d*[<>]|\{\w+\}[<>])")
_GLOB_OPTS = re.compile(r"(?:^|[;&|(\s`])(?:shopt[ \t]+-[su]|set[ \t]+(?:-[A-Za-z]*f\b|[-+]o[ \t]+noglob))")
_ANSI_C = re.compile(r"(?:(?<=[\s=;&|(`])|^)\$['\"]", re.M)   # at a word start, not a regex `$'` anchor
_PRELOAD_VAR = re.compile(r"(?<![\w])(NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|PERL5OPT|RUBYOPT"
                          r"|PYTHONPATH|PYTHONUSERBASE|PYTHONHOME|NODE_PATH|LD_LIBRARY_PATH|LD_PRELOAD"
                          r"|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|PERL5LIB|RUBYLIB|GEM_PATH|GEM_HOME)=")
_SUBST = (r"(?:\$\{[^}]*\}|\$(?:\d|[A-Za-z_]\w*)|\$\((?:[^()]|\([^()]*\))*\)|`[^`]*`)")
_SCRIPT_EXT = r"\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|php)\b"
_COMPUTED_PATH = re.compile(_SUBST + r"[\"']?[\w.\-]*(?:/|" + _SCRIPT_EXT + r")|[\w.\-]*/[\"']?" + _SUBST)
_PY_WORD = re.compile(r"(?:^|/)(?:python|pypy)(?:\d+(?:\.\d+)*)?[tw]?(?:\.exe)?$")


def _strip_comments(text: str) -> str:
    """``text`` without its shell comments: an unquoted ``#`` at a word start to the end of the
    line, the quote state carried across lines, so an apostrophe in a comment (``# don't``)
    cannot unbalance the quoting of what follows."""
    out: List[str] = []
    quote = ""
    for ln in text.splitlines():
        i, n, cut = 0, len(ln), -1
        while i < n:
            c = ln[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 2
                    continue
                if c == quote:
                    quote = ""
            elif c == "\\":
                i += 2
                continue
            elif c in "'\"":
                quote = c
            elif c == "#" and (i == 0 or ln[i - 1] in " \t;&|()"):
                cut = i
                break
            i += 1
        out.append(ln if cut < 0 else ln[:cut])
    return "\n".join(out)


def _nested_words(text: str, depth: int = 3) -> List[str]:
    """Every word of ``text``, and the words inside each word that holds blanks (a
    quoted ``-c`` string), a few levels down."""
    out: List[str] = []
    for w in _shell_words(text):
        out.append(w)
        if depth > 0 and any(c.isspace() for c in w.strip()) and len(w) < 20000:
            out += _nested_words(w, depth - 1)
    return out


def _dir_of_arg(arg: str, root: Path) -> Tuple[str, Optional[str]]:
    """Classify a directory argument. ('rel', 'x/y') a project-relative or relative
    path to join to candidates; ('root', 'x/y') a path from the project root; ('out',
    None) a directory outside the project; ('dyn', None) not literal."""
    arg = arg.strip()
    marked = _PROJECT_VAR.sub(_ROOT_MARK, arg)
    if marked.startswith(_ROOT_MARK):
        rest = marked[1:]
        if any(c in rest for c in "$`*?[{~\x00"):
            return "dyn", None
        return "root", os.path.normpath(rest.lstrip("/") or ".")
    if not arg or arg == "-" or any(c in arg for c in "$`*?[{~"):
        return "dyn", None
    if arg.startswith("/"):
        rel = _rel_or_none(Path(arg), root)
        if rel is None or rel.startswith(".."):
            return "out", None
        return "root", rel
    return "rel", os.path.normpath(arg)


class _Reached:
    """What one reached script (or settings command) contributes."""
    __slots__ = ("rel", "label", "origins", "tokens", "done", "script_dir", "kind")

    def __init__(self, rel: str, label: str, origins: Set[str], tokens: List[Tuple[str, bool]],
                 script_dir: str, kind: str) -> None:
        self.rel, self.label, self.origins, self.tokens = rel, label, origins, tokens
        self.script_dir, self.kind = script_dir, kind
        self.done = 0                    # how many candidate directories were tried


_QUOTED_STR = re.compile(r'"([^"\n]*)"|\'([^\'\n]*)\'')


def _tokens_of(text: str) -> List[Tuple[str, bool]]:
    """(candidate path, from_root) for every word and path-like substring of ``text``;
    ``from_root`` is True for a path written under $CLAUDE_PROJECT_DIR."""
    seen: Set[Tuple[str, bool]] = set()
    out: List[Tuple[str, bool]] = []

    def add(tok: str) -> None:
        from_root = tok.startswith(_ROOT_MARK)
        t = tok.replace(_ROOT_MARK, "")
        if from_root:
            t = t.lstrip("/")
        for cand in (t, t.rstrip(".")):
            if not cand or cand in (".", "..") or cand.startswith("-") or "\x00" in cand:
                continue
            key = (cand, from_root)
            if key not in seen:
                seen.add(key)
                out.append(key)

    for variant in (text.replace("\\\n", " "), text.replace("\\\n", "")):
        marked = _PROJECT_VAR.sub(_ROOT_MARK, variant)
        for m in _PATHISH.finditer(marked):
            add(m.group(0))
        for m in _QUOTED_STR.finditer(marked):          # "my hooks/x.sh", whatever the split
            q = m.group(1) if m.group(1) is not None else m.group(2)
            if q and len(q) < 1024 and ("/" in q or "." in q):
                add(q)
        for w in _nested_words(variant):
            w = _PROJECT_VAR.sub(_ROOT_MARK, w).strip()
            if w and len(w) < 1024:
                add(w)
    return out


def _dir_args(body: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """(directory arguments as ('rel'|'root', path), constructs whose directory is not
    literal) from every cd / pushd / -C / --chdir / CDPATH= / PATH= in ``body``."""
    args: List[Tuple[str, str]] = []
    dyn: List[str] = []
    for variant in (body.replace("\\\n", " "), body.replace("\\\n", "")):
        for m in _CD_ARG.finditer(variant):
            arg = m.group("dq") if m.group("dq") is not None else (
                m.group("sq") if m.group("sq") is not None else m.group("bare"))
            if arg is None:
                dyn.append("cd with no argument (the home directory)")
                continue
            kind, val = _dir_of_arg(arg, Path("/nonexistent-root"))
            if kind in ("rel", "root"):
                args.append((kind, val or "."))
            elif kind == "dyn" and arg != "-":
                dyn.append(f"{m.group('cmd')} with a variable or computed argument")
            elif kind == "out":
                dyn.append(f"{m.group('cmd')} outside the project")
        for m in _CHDIR_ARG.finditer(variant):
            arg = m.group("dq") or m.group("sq") or m.group("bare") or ""
            kind, val = _dir_of_arg(arg, Path("/nonexistent-root"))
            if kind in ("rel", "root"):
                args.append((kind, val or "."))
        for m in _PATH_ASSIGN.finditer(variant):
            value = m.group("dq") or m.group("sq") or m.group("bare") or ""
            for part in value.split(":"):
                if part in ("$PATH", "${PATH}", "$CDPATH", "${CDPATH}"):
                    continue
                kind, val = _dir_of_arg(part or ".", Path("/nonexistent-root"))
                if kind in ("rel", "root"):
                    args.append((kind, val or "."))
                elif kind == "dyn":
                    dyn.append(f"{m.group('var')} set to a computed value")
    return args, dyn


def _constructs(body: str, dyn: List[str]) -> List[str]:
    """Names of the constructs in ``body`` whose effect on paths the kit does not model."""
    found: List[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    for d in dyn:
        add(d)
    if _EVAL.search(body):
        add("eval")
    if _SOURCE_DYN.search(body):
        add("source of a computed path")
    if _FUNC_DEF.search(body):
        add("function definitions")
    if _ALIAS.search(body):
        add("alias")
    if _EXEC_REDIR.search(body):
        add("exec redirections")
    if _GLOB_OPTS.search(body):
        add("shell options that change globbing (shopt, set -f)")
    if _ANSI_C.search(body):
        add("$'...' quoting")
    if re.search(r"\bCDPATH=[^\s;&|]*[$`]", body):
        add("CDPATH set to a computed value")
    if re.search(r"\bcd(?=[\s;&|)]|$)[ \t]*(?:$|[;&|)\n])", body):
        add("cd with no argument (the home directory)")
    if _PRELOAD_VAR.search(body):
        names = sorted({m.group(1) for m in _PRELOAD_VAR.finditer(body)})
        add("a preload variable (" + ", ".join(names) + ") whose files are read by the "
            "interpreter, not named")
    scrubbed = _PROJECT_VAR.sub(_ROOT_MARK, body)
    if _COMPUTED_PATH.search(scrubbed.replace("\\\n", "")):
        add("a path built from a variable or command substitution")
    for w in _nested_words(scrubbed):
        if any(c.isspace() for c in w):
            continue
        wc = w.replace("${", "")
        if any(c in wc for c in "*?[{") and "$" not in w and (
                "/" in w or w.endswith("*") or Path(w).suffix in SCRIPT_SUFFIXES):
            add("globs or brace expansion in a word that could name a script")
    words = _nested_words(scrubbed)
    py = False
    for i, w in enumerate(words):
        if (i and _family_of(words[i - 1]) is not None and ("$" in w or "`" in w)
                and not w.startswith("-") and not any(c.isspace() for c in w)):
            add("a path built from a variable or command substitution")
        if _PY_WORD.search(w):
            kind, _ = _interp_args("python", words[i + 1:], w)
            py = py or kind == "inline"
    if py:
        add("python -m / -c programs (the modules they load are not hashed)")
    return found


#: A word that leaves the project, wherever it stands: a script can be run as a command, fed to a
#: shell (`sh < ../x`, `cat ../x | sh`) or sit inside a quoted `bash -c` string.
_OUTSIDE_COMMAND = re.compile(r"(?m)(?:^|[\s<'\"=(;&|])((?:\.\./|/)[^\s;&|()$`*?\[{<>'\"]+)")


def follow_shell_calls(root: Path, shell_scripts: Iterable[str],
                       texts: Iterable[Tuple[str, str]] = (),
                       registered: Iterable[str] = ()
                       ) -> Tuple[Dict[str, Set[str]], Set[str], Set[str], List[str]]:
    """The project files that shell hooks reach, by a conservative rule that does not
    model the shell (see the section comment). ``texts`` are extra (origin label, text)
    pairs, the command lines of registrations, scanned from the project root like a
    script. Returns ({rel file: origin stems}, shell files reached, python files
    reached, NOT CHECKED notes). Raises NotEvaluable past the work budget."""
    called: Dict[str, Set[str]] = {}
    shells: Set[str] = set()
    pys: Set[str] = set()
    notes: List[str] = []
    known = set(registered)
    wanted: List[Tuple[str, str]] = []
    infos: List[_Reached] = []
    queued: Set[str] = set()
    pending: List[Tuple[str, Set[str]]] = []
    budget = {"files": 0, "bytes": 0, "stats": 0}
    dir_set: Set[str] = {""}
    dir_list: List[str] = [""]
    cd_args: Set[Tuple[str, str]] = set()
    base_dirs: Set[str] = {""}
    closure_dirty = [True]

    def exhausted(what: str) -> NotEvaluable:
        return NotEvaluable(
            f"following the project files shell hooks reach went past its work budget "
            f"({what}; limits: {FOLLOW_MAX_FILES} files, {FOLLOW_MAX_BYTES} bytes, "
            f"{FOLLOW_MAX_DIRS} directories, {FOLLOW_MAX_STATS} path checks): NOT EVALUABLE")

    def add_dir(d: str) -> None:
        if d not in dir_set:
            if len(dir_list) >= FOLLOW_MAX_DIRS:
                raise exhausted("directories")
            dir_set.add(d)
            dir_list.append(d)

    def close_dirs() -> None:
        for b in sorted(base_dirs):
            add_dir(b)
        changed = True
        while changed:
            changed = False
            for kind, a in sorted(cd_args):
                bases = [""] if kind == "root" else list(dir_list)
                for d in bases:
                    budget["stats"] += 1
                    if budget["stats"] > FOLLOW_MAX_STATS:
                        raise exhausted("path checks")
                    cand = os.path.normpath(os.path.join(d, a))
                    if cand == ".":
                        cand = ""
                    if cand.startswith("..") or cand in dir_set:
                        continue
                    if (root / cand).is_dir():
                        add_dir(cand)
                        changed = True
        closure_dirty[0] = False

    def scan(label: str, text: str, rel: str, script_dir: str, origins: Set[str],
             kind: str) -> None:
        budget["files"] += 1
        budget["bytes"] += len(text)
        if budget["files"] > FOLLOW_MAX_FILES or budget["bytes"] > FOLLOW_MAX_BYTES:
            raise exhausted("files or bytes")
        body = _strip_comments(text)
        args, dyn = _dir_args(body)
        if base_dirs.isdisjoint({script_dir}) and script_dir not in base_dirs:
            base_dirs.add(script_dir)
            closure_dirty[0] = True
        for a in args:
            if a not in cd_args:
                cd_args.add(a)
                closure_dirty[0] = True
        marked = _PROJECT_VAR.sub(_ROOT_MARK, body)
        try:
            lex = shlex.shlex(marked, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            lex.commenters = ""
            top = list(lex)
        except ValueError:
            notes.append(f"{label} could not be split into shell words (an unbalanced quote); a "
                         "quoted path in it may be missed")
            top = [t for t in (_unquote(x) for x in marked.split()) if t]
        # the first file operand of an interpreter (or run-parts), at the top level only: one
        # that does not resolve, or that is a directory, is named after the walk
        for i, w in enumerate(top):
            fam = _family_of(w)
            x = None
            if fam is not None:
                akind, val = _interp_args(fam, top[i + 1:], w)
                if akind == "file":
                    x = val
            elif w.rsplit("/", 1)[-1] == "run-parts":
                x = next((y for y in top[i + 1:] if not y.startswith("-")), None)
            if (x and not _is_op(x) and not any(c in x for c in "$`*?[{<>")
                    and x not in ("", ".", "..")):
                wanted.append((label, x))
        for i, w in enumerate(top[:-1]):
            if w in (".", "source") and (i == 0 or _is_op(top[i - 1])):
                x = top[i + 1]
                if not _is_op(x) and not any(c in x for c in "$`*?[{<>"):
                    wanted.append((label, x))
        for m in _OUTSIDE_COMMAND.finditer(body):
            x = m.group(1)
            if x.startswith("..") or Path(x).suffix in SCRIPT_SUFFIXES:
                wanted.append((label, x))
        names = _constructs(body, dyn)
        if names:
            notes.append(f"{label}: uses {', '.join(names)}; a script it runs by a computed "
                         "path is not hashed")
        infos.append(_Reached(rel, label, origins, _tokens_of(body), script_dir, kind))

    def read_script(rel: str, origins: Set[str]) -> None:
        path = root / rel
        try:
            size = path.stat().st_size
            if budget["bytes"] + size > FOLLOW_MAX_BYTES:
                raise exhausted("bytes")
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise NotEvaluable(f"cannot read {rel} to follow what it runs: {e}") from e
        sd = Path(rel).parent.as_posix()
        scan(rel, text, rel, "" if sd == "." else sd, origins, "shell")

    def reach(trel: str, by: _Reached) -> None:
        if trel == by.rel:
            return
        if not (by.kind == "text" and trel in known):
            called.setdefault(trel, set()).update(by.origins)
        if trel in queued:
            return
        queued.add(trel)
        sk = _script_kind(root / trel)
        if sk == "python":
            pys.add(trel)
        elif sk == "shell":
            shells.add(trel)
            pending.append((trel, set(by.origins)))
        else:
            if Path(trel).suffix in SCRIPT_SUFFIXES:
                notes.append(f"{trel} is reached from {by.label} and is not shell or Python: "
                             "hashed, but what it runs is not followed")
            try:
                budget["bytes"] += (root / trel).stat().st_size
            except OSError:
                pass
            if budget["bytes"] > FOLLOW_MAX_BYTES:
                raise exhausted("bytes")

    for r in sorted(set(shell_scripts)):
        if (root / r).is_file() and r not in queued:
            queued.add(r)
            pending.append((r, {Path(r).stem}))
    text_labels = set()
    for label, text in texts:
        text_labels.add(label)
        scan(label, text, "", "", {label}, "text")

    while True:
        progressed = False
        while pending:
            rel, origins = pending.pop()
            read_script(rel, origins)
            progressed = True
        if closure_dirty[0]:
            close_dirs()
            progressed = True
        for info in infos:
            if info.done >= len(dir_list):
                continue
            new_dirs = dir_list[info.done:]
            info.done = len(dir_list)
            progressed = True
            for tok, from_root in info.tokens:
                for d in ([""] if from_root else new_dirs):
                    budget["stats"] += 1
                    if budget["stats"] > FOLLOW_MAX_STATS:
                        raise exhausted("path checks")
                    if tok.startswith("/"):
                        rel = _rel_or_none(Path(tok), root) or ".."
                    else:
                        rel = os.path.normpath(os.path.join(d, tok))
                    if rel.startswith("..") or os.path.isabs(rel) or rel == ".":
                        continue
                    p = root / rel
                    try:
                        if not p.is_file():
                            continue
                    except (OSError, ValueError):
                        continue
                    if rel == BASELINE_REL.as_posix() or rel.split("/")[0] == ".git" and \
                            _script_kind(p) is None:
                        continue
                    reach(rel, info)
        if not progressed:
            break
    for label, w in wanted:
        from_root = w.startswith(_ROOT_MARK)
        w = w.replace(_ROOT_MARK, "").lstrip("/") if from_root else w
        if w.startswith("/"):
            rel_abs = _rel_or_none(Path(w), root)
            hit = rel_abs is not None and (root / rel_abs).is_file()
            outside = rel_abs is None or rel_abs.startswith("..")
            if outside:
                # a settings command's absolute script is already named by the registration check
                if label not in text_labels:
                    notes.append(f"{label} runs {w[:80]}, a script outside the project: not hashed")
                continue
        else:
            joined = [os.path.normpath(os.path.join(d, w)) for d in ([""] if from_root else dir_list)]
            cands = [root / j for j in joined if not j.startswith("..")]
            hit = any(c.is_file() for c in cands)
            if not hit and len(cands) < len(joined):
                if label not in text_labels:
                    notes.append(f"{label} names {w[:80]}, outside the project: not hashed if it runs")
                continue
            if not hit and any(c.is_dir() for c in cands):
                notes.append(f"{label} runs a directory, {w[:80]} (a `__main__.py` or the scripts in "
                             "it): not hashed; list what it runs in integrity.extra_files")
                continue
        if not hit:
            notes.append(f"{label} runs {w[:80]}, which is not a file where the script is run "
                         "(the project root, the script's directory or a directory it moves "
                         "to): not followed")
    return called, shells, pys, notes


# ── bytecode caches ─────────────────────────────────────────────────────────

def _pyc_files(src: Path) -> List[Path]:
    cache = src.parent / "__pycache__"
    if not cache.is_dir():
        return []
    stem = src.stem + "."
    return [cache / n for n in _listdir(cache)
            if n.startswith(stem) and n.endswith(".pyc") and n.count(".") - src.stem.count(".") in (2, 3)]


def pyc_verdict(src: Path, pyc: Path, data: bytes) -> str:
    """'match' | 'mismatch' | 'unused' | 'foreign' for one cache file.

    For this interpreter's own tag the check is exact: decide whether the
    import system would load the file (magic, then the timestamp or hash
    header), and if so, compile the source and compare code objects. For another
    interpreter's tag nothing here can decode it: 'foreign'."""
    tag = pyc.name[len(src.stem) + 1:].split(".")[0]
    if tag != sys.implementation.cache_tag:
        return "foreign"
    if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
        return "unused"
    try:
        src_bytes = src.read_bytes()
        st = src.stat()
    except OSError as e:
        raise NotEvaluable(f"cannot read {src} to check its bytecode: {e}") from e
    flags = int.from_bytes(data[4:8], "little")
    if flags & 0b1:                               # hash-based pyc
        used = not (flags & 0b10) or data[8:16] == importlib.util.source_hash(src_bytes)
    else:
        used = (data[8:12] == (int(st.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little")
                and data[12:16] == (st.st_size & 0xFFFFFFFF).to_bytes(4, "little"))
    if not used:
        return "unused"
    opt = 2 if ".opt-2." in pyc.name else 1 if ".opt-1." in pyc.name else 0
    try:
        code = marshal.loads(data[16:])
        expected = compile(src_bytes, str(src), "exec", dont_inherit=True, optimize=opt)
    except Exception:                              # noqa: BLE001 - undecodable is a mismatch
        return "mismatch"
    return "match" if code == expected else "mismatch"


def bytecode_surface(root: Path, sources: Iterable[str]) -> Dict[str, dict]:
    """{rel pyc: {'payload': sha256 of the code payload, 'verdict': ...}} for the
    caches beside every covered module. The payload hash skips the 16-byte
    header, so a cache rewritten for a new source mtime is not a change."""
    out: Dict[str, dict] = {}
    for rel in sorted(set(sources)):
        src = root / rel
        for pyc in _pyc_files(src):
            try:
                data = pyc.read_bytes()
            except OSError as e:
                raise NotEvaluable(f"cannot read bytecode {pyc} to check it: {e}") from e
            prel = _rel_or_none(pyc, root) or str(pyc)
            out[prel] = {"payload": hashlib.sha256(data[16:]).hexdigest(),
                         "verdict": pyc_verdict(src, pyc, data),
                         "tag": pyc.name[len(src.stem) + 1:].split(".")[0]}
    return out


def bad_glob_reason(pattern: object) -> Optional[str]:
    """Why ``pattern`` cannot be an ``integrity.extra_files`` glob, or None. A glob must
    be a non-empty, relative pattern that names something inside the project: no
    leading ``/`` or ``~``, no drive letter, no ``..`` component, no NUL byte, and
    at least one component that is not just ``.``."""
    if not isinstance(pattern, str):
        return "it is not a string"
    if not pattern.strip():
        return "it is empty"
    if "\x00" in pattern:
        return "it contains a NUL byte"
    norm = pattern.replace("\\", "/")
    if norm.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", norm):
        return "it is not relative to the project"
    parts = [c for c in norm.split("/") if c not in ("", ".")]
    if not parts:
        return "it names the project directory itself, not files in it"
    if ".." in parts:
        return "it leaves the project (a `..` component)"
    return None


def extra_files(root: Path, globs: Sequence[str], notes: Optional[List[str]] = None
                ) -> List[str]:
    """Project-relative files matched by the ``integrity.extra_files`` globs. A glob
    that is not a relative pattern inside the project is NOT EVALUABLE, named: it is
    never skipped (a silently dropped glob would read as covered). A glob that matches
    the baseline file is told so and the baseline is left out (it cannot hash itself);
    a glob that matches no file is named in ``notes`` (0 files matched, exit 0)."""
    found: set = set()
    for pattern in globs:
        why = bad_glob_reason(pattern)
        if why:
            raise NotEvaluable(f"integrity.extra_files glob {str(pattern)[:80]!r} is unusable: "
                               f"{why}. Fix .claude/hook-integrity-kit.json (or re-bless "
                               "after fixing it)")
        try:
            hits = [p for p in root.glob(pattern) if p.is_file()]
        except (ValueError, NotImplementedError, OSError, RecursionError) as e:
            raise NotEvaluable(f"integrity.extra_files glob {pattern[:80]!r} cannot be "
                               f"evaluated ({type(e).__name__}: {str(e)[:80]}): NOT "
                               "EVALUABLE") from e
        kept = 0
        for p in hits:
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                raise NotEvaluable(f"integrity.extra_files glob {pattern[:80]!r} matched "
                                   f"{p}, outside the project") from None
            if rel == BASELINE_REL.as_posix():
                if notes is not None:
                    notes.append(f"integrity.extra_files glob {pattern[:80]!r} matches the "
                                 "baseline file itself, which cannot hash itself: excluded")
                continue
            kept += 1
            found.add(rel)
        if kept == 0 and notes is not None:
            notes.append(f"integrity.extra_files glob {pattern[:80]!r}: 0 files matched, "
                         "nothing is hashed for it")
    return sorted(found)


def _kit_pkg(pkg: Optional[Path]) -> Path:
    return pkg or Path(__file__).resolve().parent


def kit_self_files(pkg: Optional[Path] = None) -> Dict[str, str]:
    """{'hook_integrity_kit/<file>.py': sha256} for the kit's own source. Keyed by
    package-relative name, so two people on the same kit version agree."""
    pkg = _kit_pkg(pkg)
    return {f"{pkg.name}/{p.name}": sha256_file(p) for p in sorted(pkg.glob("*.py"))}


def kit_bytecode_mismatches(pkg: Optional[Path] = None) -> List[str]:
    """The kit's own bytecode caches that this interpreter would load and that
    do not match their source: a swapped guard that leaves the ``.py`` alone."""
    pkg = _kit_pkg(pkg)
    bad = []
    for src in sorted(pkg.glob("*.py")):
        for pyc in _pyc_files(src):
            try:
                data = pyc.read_bytes()
            except OSError:
                bad.append(f"{pkg.name}/__pycache__/{pyc.name} (unreadable)")
                continue
            if pyc_verdict(src, pyc, data) == "mismatch":
                bad.append(f"{pkg.name}/__pycache__/{pyc.name}")
    return bad


# ── the user-level (global) surface: warn-only ───────────────────────────────

def _global_script_paths(entry: dict) -> List[Path]:
    """Absolute script files a global entry references. Global registrations use
    ``~`` or absolute paths, never ``${CLAUDE_PROJECT_DIR}``, so tokens are
    resolved directly. Quotes survive a whitespace split and must be stripped:
    a quoted ``"$HOME/.claude/hooks/x"`` otherwise expands to a quoted path that
    is not a file, every token drops, and coverage goes to zero without a word."""
    out: List[Path] = []
    for tok, _ in _entry_words(entry):
        whole = Path(os.path.expandvars(os.path.expanduser(tok.strip("\"'"))))
        if any(c.isspace() for c in tok) and whole.is_absolute() and whole.is_file():
            out.append(whole)
            continue
        for piece in tok.split():
            p = Path(os.path.expandvars(os.path.expanduser(piece.strip("\"'"))))
            if p.is_absolute() and p.is_file():
                out.append(p)
    return out


def build_global_section(global_dir: Optional[Path] = None) -> dict:
    gdir = global_dir or (Path.home() / ".claude")
    settings = gdir / "settings.json"
    section: dict = {"covered": True, "settings_hooks_sha256": None,
                     "registrations": [], "files": []}
    if not settings.is_file():
        return section
    try:
        data = load_settings(settings)
    except NotEvaluable:
        section["settings_hooks_sha256"] = "unreadable"
        return section
    hooks_block = data.get("hooks") or {}
    section["settings_hooks_sha256"] = settings_hash(data)
    seen: Dict[str, dict] = {}
    unresolved = 0
    for event, entry in _entries(hooks_block):
        section["registrations"].append({"event": event, "command": " ".join(_texts(entry))})
        paths = _global_script_paths(entry)
        if not paths:
            unresolved += 1
        for p in paths:
            seen.setdefault(str(p), {"path": str(p), "sha256": sha256_file(p)})
    section["files"] = [seen[k] for k in sorted(seen)]
    # Each registration with no hashable file is a coverage hole, not a clean
    # surface: that hook's body can be swapped with nothing noticing. Counted
    # per registration: one resolving sibling used to hide every other hole.
    section["unresolved_registrations"] = unresolved
    return section


def check_global(baseline: dict, global_dir: Optional[Path] = None) -> dict:
    """Global drift, by name. Never returns a ``status`` key: the repo verdict
    cannot be flipped by ~/.claude churn."""
    out: dict = {"global_status": "clean", "global_changes": [],
                 "global_registration_count": 0}
    recorded = baseline.get("global")
    if isinstance(recorded, dict) and recorded.get("covered") is False:
        out["global_status"] = "off"
        return out
    current = build_global_section(global_dir)
    out["global_registration_count"] = len(current["registrations"])
    if not recorded:
        out["global_status"] = "not-covered"
        out["global_changes"].append(
            "this baseline predates global coverage; re-bless with --include-global to adopt")
        return out
    if recorded.get("settings_hooks_sha256") != current["settings_hooks_sha256"]:
        out["global_status"] = "drift"
        rec = {(r["event"], r["command"]) for r in recorded.get("registrations", [])}
        cur = {(r["event"], r["command"]) for r in current["registrations"]}
        for ev, cmd in sorted(cur - rec):
            out["global_changes"].append(f"NEW global hook [{ev}]: {cmd}")
        for ev, cmd in sorted(rec - cur):
            out["global_changes"].append(f"GONE global hook [{ev}]: {cmd}")
        if not (cur - rec) and not (rec - cur):
            out["global_changes"].append("global hooks block changed (matcher/order/config)")
    rec_files = {f["path"]: f.get("sha256") for f in (recorded.get("files") or [])}
    cur_files = {f["path"]: f["sha256"] for f in current["files"]}
    # The union, so a recorded script that vanished (or stopped resolving) is
    # named, not just scripts that are still there and changed.
    for path in sorted(set(rec_files) | set(cur_files)):
        if path not in cur_files:
            out["global_status"] = "drift"
            out["global_changes"].append(f"global hook script GONE or unreadable: {path}")
        elif path in rec_files and rec_files[path] != cur_files[path]:
            out["global_status"] = "drift"
            out["global_changes"].append(f"global hook script CONTENT changed: {path}")
    if current.get("unresolved_registrations"):
        out["global_status"] = "drift"
        out["global_changes"].append(
            f"global hook CONTENT IS UNCHECKED: {current['unresolved_registrations']} "
            "registration(s) resolve to no readable script, so a body swap would be "
            "invisible. This is a coverage hole, NOT a clean surface")
    return out


# ── surfaces outside the project that this kit does not hash ────────────────

#: Where Claude Code reads managed (enterprise) settings from, per its settings
#: documentation: Linux/WSL, macOS, Windows. ``HOOK_INTEGRITY_MANAGED_DIRS``
#: (an ``os.pathsep``-separated list) replaces them, for tests and nonstandard installs.
MANAGED_SETTINGS_DIRS = ("/etc/claude-code", "/Library/Application Support/ClaudeCode",
                         "C:\\Program Files\\ClaudeCode")


def _shown(p: Path) -> str:
    try:
        return "~/" + p.relative_to(Path.home()).as_posix()
    except (ValueError, RuntimeError):
        return str(p)


def managed_settings_files() -> List[Path]:
    env = os.environ.get("HOOK_INTEGRITY_MANAGED_DIRS")
    dirs = [d for d in env.split(os.pathsep) if d] if env is not None else MANAGED_SETTINGS_DIRS
    found: List[Path] = []
    for d in dirs:
        base = Path(d)
        try:
            if (base / "managed-settings.json").is_file():
                found.append(base / "managed-settings.json")
            dropin = base / "managed-settings.d"
            if dropin.is_dir():
                found += sorted(p for p in dropin.glob("*.json") if p.is_file())
        except OSError:
            continue
    return found


def out_of_scope_notes(global_dir: Optional[Path] = None, global_covered: bool = False) -> List[str]:
    """``NOT CHECKED`` lines for surfaces that run hooks in this project's sessions
    but live outside it, when they exist on this machine: the user's installed
    plugins, user-level settings hooks (unless the baseline covers ``~/.claude``),
    and managed settings files. Presence only: absent means no line. What this does
    NOT see is listed in docs/coverage.md (remote-managed settings, MDM and registry
    policy, ``~/.claude.json``, user-level skills and agents, ``--settings`` files)."""
    notes: List[str] = []
    gdir = global_dir or (Path.home() / ".claude")
    try:
        plug = gdir / "plugins"
        if ((plug / "cache").is_dir() or (plug / "installed_plugins.json").is_file()
                or (plug / "marketplaces").is_dir()):
            notes.append(f"installed plugins under {_shown(plug)} (the user plugin cache): the "
                         "hooks they register run in your sessions and are not read or hashed")
        settings = gdir / "settings.json"
        if not global_covered and settings.is_file():
            try:
                n = sum(1 for _ in _entries(load_settings(settings).get("hooks") or {}))
            except NotEvaluable:
                notes.append(f"user-level settings {_shown(settings)} cannot be read; any hooks "
                             "in it are not checked")
                n = 0
            if n:
                notes.append(f"user-level hooks in {_shown(settings)} ({n} registration(s)) are "
                             "not hashed: this baseline does not cover ~/.claude "
                             "(re-bless with --include-global to warn on changes)")
    except OSError:
        pass
    for f in managed_settings_files():
        notes.append(f"managed (enterprise) settings file {f}: not read or hashed; any hooks "
                     "it registers run in your sessions")
    return notes


# ── build and check ──────────────────────────────────────────────────────────

# ── trust settings: what widens what the agent may do without asking ──────────

_MODE_RANK = {"plan": 0, "dontAsk": 0, "default": 1, "acceptEdits": 2, "auto": 2, "bypassPermissions": 3}

#: `Bash(python3:*)` is as wide as `Bash`: each of these runs whatever it is handed.
_RUNS_ANYTHING = re.compile(
    r"^(?:Bash|PowerShell)\(\s*(?:sudo\s+)?(?:[\w./~-]*/)?(?:"
    r"(?:python[\d.]*|sh|bash|zsh|dash|ksh|fish|pwsh|node|deno|bun|perl|ruby|php|lua)(?:\s+-[a-zA-Z]+)?"
    r"|env|xargs|eval|exec|sudo|npx|uvx"
    r"|pip[\d.]*(?:\s+install)?|uv(?:\s+run|\s+pip\s+install)?"
    r"|(?:npm|pnpm|yarn)(?:\s+(?:run|install|exec))?"
    r")(?:\s*:\s*\*|\s+\*|\*)\s*\)$", re.I)


def _broad_rule(rule: str) -> bool:
    """An allow rule that covers a whole tool, or every input of one: `Bash`, `Bash(*)`,
    `Bash(*:*)`, `Write`, `*`."""
    r = rule.strip()
    if re.fullmatch(r"mcp__[\w-]+__[\w-]+", r):
        return False                       # one named MCP tool, not a whole server
    if _RUNS_ANYTHING.match(r):
        return True
    return (r == "*" or re.fullmatch(r"[A-Za-z_][\w-]*", r) is not None
            or re.fullmatch(r"[A-Za-z_][\w-]*\(\s*\*+(?::\*+)?\s*\)", r) is not None
            or re.fullmatch(r"[A-Za-z_][\w-]*\*", r) is not None)          # mcp__*


#: An allow rule for a command that reaches the network: once allowed, data can leave without a
#: prompt (PromptArmor's plugin hook added `Bash(curl:*)` to settings.local.json for this).
_EGRESS_RULE = re.compile(
    r"^\s*(?:Bash|PowerShell)\(\s*(?:sudo\s+)?(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync"
    r"|ftp|tftp|telnet|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", re.I)


def egress_rule(rule: str) -> bool:
    return _EGRESS_RULE.match(rule) is not None


def shown_rule(rule: str) -> str:
    """An allow rule as the baseline and reports hold it. `Bash(curl:*)` as written; anything
    longer can carry a token in its arguments, and settings.local.json is not committed while
    the baseline is, so it becomes the command word plus a hash. Applying this twice changes
    nothing."""
    if "#sha256:" in rule or re.fullmatch(r"\s*\w+\(\s*[\w.-]+(?:\s*:\s*\*)?\s*\)\s*", rule):
        return rule
    m = re.match(r"\s*(\w+\(\s*(?:sudo\s+)?[\w.-]+)", rule)
    return f"{m.group(1) if m else 'rule'} ...)#sha256:{hashlib.sha256(rule.encode()).hexdigest()[:16]}"


def trust_snapshot(root: Path, settings: Optional[Sequence[Path]] = None) -> Dict[str, dict]:
    """{settings label: {mode, broad_allow, egress_allow, all_project_mcp, hooks_disabled, dirs}}
    for each settings file."""
    out: Dict[str, dict] = {}
    for sp in _settings_paths(root, settings):
        if not sp.is_file():
            continue
        data = load_settings(sp)
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
        out[_label(root, sp)] = {
            "mode": perms.get("defaultMode") if isinstance(perms.get("defaultMode"), str) else None,
            "broad_allow": sorted(a for a in allow if _broad_rule(a)),
            "egress_allow": sorted(shown_rule(a) for a in allow if egress_rule(a) and not _broad_rule(a)),
            # as written: a removed rule must say what it was, and these rarely hold a token
            "deny": sorted(a for a in perms.get("deny") or [] if isinstance(a, str)),
            "ask": sorted(a for a in perms.get("ask") or [] if isinstance(a, str)),
            "all_project_mcp": data.get("enableAllProjectMcpServers") is True,
            "hooks_disabled": data.get("disableAllHooks") is True,
            "dirs": sorted(d for d in perms.get("additionalDirectories") or [] if isinstance(d, str)),
        }
    return out


def escalations(before: Dict[str, dict], now: Dict[str, dict]) -> List[str]:
    """What widened between two trust snapshots. Narrowing is not reported."""
    out: List[str] = []
    for label, cur in sorted(now.items()):
        # a settings file that did not exist at the bless is compared from empty
        old = before.get(label, {"mode": None, "broad_allow": [], "egress_allow": [],
                                 "all_project_mcp": False, "hooks_disabled": False, "dirs": []})
        was, mode = old["mode"] or "default", cur["mode"] or "default"
        if mode not in _MODE_RANK and mode != was:
            out.append(f"{label}: permissions.defaultMode is now {mode}, which this kit cannot "
                       f"rank (was {was})")
        elif _MODE_RANK.get(mode, 1) > _MODE_RANK.get(was, 1):
            out.append(f"{label}: permissions.defaultMode is now {cur['mode']} (was {was})")
        for r in sorted(set(cur["broad_allow"]) - set(old["broad_allow"])):
            out.append(f"{label}: blanket allow rule added: {r}")
        # keys a baseline written by an older kit does not hold are not compared: unknown is
        # not "newly added" (the KIT_CHANGED finding asks for a re-bless anyway)
        if "egress_allow" in old:
            held = {shown_rule(r) for r in old["egress_allow"]}
            for r in sorted({shown_rule(r) for r in cur.get("egress_allow", [])} - held):
                out.append(f"{label}: network command allowed without a prompt: {r}")
        for key, what in (("deny", "deny"), ("ask", "ask")):
            if key in old:
                for r in sorted(set(old[key]) - set(cur.get(key, []))):
                    out.append(f"{label}: {what} rule removed: {r}")
        if "hooks_disabled" in old and cur.get("hooks_disabled") and not old["hooks_disabled"]:
            out.append(f"{label}: disableAllHooks turned on (no hook runs, this kit's included)")
        if cur["all_project_mcp"] and not old["all_project_mcp"]:
            out.append(f"{label}: enableAllProjectMcpServers turned on (every project MCP "
                       "server approved without a prompt)")
        for d in sorted(set(cur["dirs"]) - set(old["dirs"])):
            out.append(f"{label}: additional directory allowed: {d}")
    return out


def diff_since_baseline(root: Path, baseline_path: Path, rel: str, max_lines: int = 200) -> str:
    """The git diff of ``rel`` since the commit that last wrote the baseline (HEAD when the
    baseline was never committed), for `bless --diff`. Says why when there is none."""
    import subprocess

    def git(*args: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                              timeout=30)
    try:
        inside = git("rev-parse", "--is-inside-work-tree")
        log = git("log", "-1", "--format=%H", "--", str(baseline_path))
    except (OSError, subprocess.TimeoutExpired):
        return "  (no diff: git is not available)"
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return "  (no diff: not a git checkout)"
    ref = log.stdout.strip() if log.returncode == 0 else ""
    if not ref:
        return ("  (no diff: no commit has written the baseline yet; commit it once and later "
                "re-blesses diff against it)")
    d = git("diff", "--no-color", ref, "--", rel)
    if d.returncode != 0:
        return f"  (no diff: git could not compare against {ref[:12]})"
    lines = d.stdout.splitlines()
    if not lines:
        return "  (no diff: git shows no change since the baseline commit; the file may be untracked)"
    more = len(lines) - max_lines
    shown = lines[:max_lines] + ([f"  ... {more} more line(s)"] if more > 0 else [])
    return "\n".join("  " + ln for ln in shown)


def _settings_paths(root: Path, settings: Optional[Sequence[Path]]) -> List[Path]:
    return list(settings) if settings else [root / r for r in SETTINGS_RELS]


def _label(root: Path, p: Path) -> str:
    return _rel_or_none(p.resolve(), root.resolve()) or str(p)


def _command_setting_notes(data: dict, label: str) -> List[str]:
    out = []
    for key in COMMAND_SETTINGS_KEYS:
        if key in data:
            v = data[key]
            shown = v.get("command", "") if isinstance(v, dict) else v
            out.append(f"`{key}` in {label} runs a command (the setting is pinned, the script it "
                       f"runs is not followed): "
                       f"{str(shown)[:120]}")
    return out


_PACKAGE_RUNNERS = frozenset(("npx", "uvx", "pipx", "bunx", "pnpx", "yarn", "pnpm", "docker",
                              "podman", "deno", "go"))


def _mcp_servers(root: Path) -> Tuple[List[Tuple[str, str]], List[str]]:
    """([(project file a server runs, server name)], NOT CHECKED notes) for `.mcp.json`.
    Claude Code starts a stdio server in the project directory, so a word of its command or
    args that names a project file (relative, or under ``${CLAUDE_PROJECT_DIR}``) is a file
    the server runs. A remote server, or one started from an installed package, has nothing
    on disk here to hash, and is named."""
    try:
        data = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return [], [f"MCP server config .mcp.json could not be parsed ({e.__class__.__name__}); "
                    "its bytes are hashed, its servers are not followed"]
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    files: List[Tuple[str, str]] = []
    notes: List[str] = []
    rroot = root.resolve()
    for name, srv in sorted((servers or {}).items()) if isinstance(servers, dict) else []:
        if not isinstance(srv, dict):
            continue
        if srv.get("url") or srv.get("type") in ("sse", "http"):
            notes.append(f"MCP server '{name}' in .mcp.json is remote ({srv.get('url', '?')}): "
                         "what it serves is not on disk, NOT CHECKED")
            continue
        cmd = str(srv.get("command", ""))
        args = [str(a) for a in srv.get("args") or []]
        found = False
        for w in [cmd] + args:
            w2 = re.sub(r"^\$\{?CLAUDE_PROJECT_DIR\}?/", "", w)
            if not w2 or w2.startswith("-"):
                continue
            cand = root / w2
            if cand.is_file() and _rel_or_none(cand.resolve(), rroot) is not None:
                files.append((_rel_or_none(cand, root) or w2, name))
                found = True
        shown = " ".join([cmd] + args)
        if os.path.basename(cmd) in _PACKAGE_RUNNERS:
            notes.append(f"MCP server '{name}' in .mcp.json runs `{shown}`: an installed "
                         "package this kit does not hash; pin its version")
        elif not found:
            notes.append(f"MCP server '{name}' in .mcp.json runs `{shown}`: no project file it "
                         "names was found, so what it runs is NOT CHECKED")
    return files, notes


def current_surface(root: Path, settings: Optional[Sequence[Path]] = None,
                    extra_globs: Sequence[str] = ()) -> dict:
    """Everything the baseline hashes, computed from disk now."""
    settings_hashes: Dict[str, str] = {}
    regs = Registrations(root)
    command_notes: List[str] = []
    for sp in _settings_paths(root, settings):
        data = load_settings(sp)
        label = _label(root, sp)
        settings_hashes[label] = settings_hash(data)
        regs.add_block(data.get("hooks") or {}, label)
        command_notes += _command_setting_notes(data, label)
    plugin_files = plugin_inventory(root, regs)

    entries: Dict[str, dict] = {}

    def add(rel: str, events: Sequence[str]) -> None:
        path = root / rel
        prev = set(entries.get(rel, {}).get("events", []))
        if not path.is_file():
            entries[rel] = {"path": rel, "sha256": None, "events": sorted(prev | set(events))}
            return
        try:
            digest = sha256_file(path)
        except OSError as e:
            raise NotEvaluable(f"cannot read {rel} to hash it: {e}") from e
        e = entries.setdefault(rel, {"path": rel, "sha256": digest, "events": []})
        mode = _exec_bit(path)
        if mode is not None:
            e["exec"] = mode
        e["events"] = sorted(set(e["events"]) | set(events))
        if path.is_symlink():
            # Same bytes behind a new link target can still change what runs:
            # Python puts the RESOLVED directory on sys.path.
            e["link"] = os.readlink(path)

    for rel, events in sorted(regs.scripts.items()):
        add(rel, sorted(events))
    # MCP servers: the config itself, and the project files a stdio server runs
    mcp_notes: List[str] = []
    mcp_py: Set[str] = set()
    if (root / ".mcp.json").is_file():
        add(".mcp.json", [EVENT_MCP])
        mfiles, mcp_notes = _mcp_servers(root)
        for rel, name in mfiles:
            add(rel, [f"{EVENT_MCP}:{name}"])
            if _script_kind(root / rel) == "python":
                mcp_py.add(rel)
    for rel in plugin_files:
        add(rel, [EVENT_PLUGIN_REG])
    called, called_shells, called_py, call_notes = follow_shell_calls(
        root, regs.shell, regs.texts, regs.scripts)
    for rel, origins in sorted(called.items()):
        add(rel, [f"{EVENT_CALLED}:{o}" for o in sorted(origins)])
    python_entries = {r for r in regs.python | called_py | mcp_py if (root / r).is_file()}
    imported, import_notes, sources = import_walk(root, python_entries)
    for rel, origins in imported.items():
        add(rel, [f"{EVENT_IMPORTED}:{o}" for o in origins])
    for rel, origins in stdlib_shadows(root, python_entries).items():
        add(rel, [f"{EVENT_IMPORTED}:{o}" for o in origins])
    if (root / CONFIG_REL).is_file():
        add(CONFIG_REL.as_posix(), [EVENT_KIT_CONFIG])
    extra_notes: List[str] = []
    for rel in extra_files(root, extra_globs, extra_notes):
        add(rel, [EVENT_EXTRA])

    not_checked = (list(regs.not_checked) + command_notes + call_notes + import_notes
                   + extra_notes + mcp_notes)
    for rel in frontmatter_hook_files(root):
        if rel.endswith(" (unreadable)"):
            not_checked.append(f"hooks declared in frontmatter: {rel} (not parsed or hashed)")
            continue
        # The file is hashed, so a new one is ADDED and an edit is MODIFIED; the hooks inside
        # are not parsed, so what they run is still not followed.
        add(rel, [EVENT_FRONTMATTER])
        not_checked.append(f"hooks declared in frontmatter: {rel} (file hashed; the hooks "
                           "inside are not parsed, so scripts they run are not followed)")
    for rel in venv_startup_files(root, [t for _o, t in regs.texts]):
        not_checked.append(f"{rel} runs at every start of the virtualenv a hook uses (not hashed: "
                           "it differs per machine, so read this list)")
    return {"settings": settings_hashes, "entries": entries,
            "external": sorted(regs.external), "kit_registrations": regs.kit_registrations,
            "not_checked": not_checked, "bytecode": bytecode_surface(root, sources)}


def build_baseline(root: Path, settings: Optional[Sequence[Path]] = None,
                   extra_globs: Sequence[str] = (), include_global: bool = False,
                   global_dir: Optional[Path] = None,
                   not_checked_out: Optional[List[str]] = None) -> dict:
    """The baseline for the current surface. ``not_checked_out``, when given, receives
    the project's ``NOT CHECKED`` lines (the ones ``verify`` prints), which are not
    stored in the baseline: ``bless`` shows them so the review sees what it cannot hash."""
    surf = current_surface(root, settings, extra_globs)
    if not_checked_out is not None:
        not_checked_out.extend(surf["not_checked"])
    listed = set(surf["entries"])
    return {
        "version": BASELINE_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "settings_hooks_sha256": surf["settings"],
        "trust": trust_snapshot(root, settings),
        "files": [surf["entries"][k] for k in sorted(surf["entries"])],
        "bytecode": {k: v["payload"] for k, v in sorted(surf["bytecode"].items())},
        "unregistered_on_disk": [p for p in on_disk_hook_scripts(root) if p not in listed],
        "external_unchecked": [{"event": ev, "path": p} for ev, p in surf["external"]],
        "extra_globs": list(extra_globs),
        "kit": {"files": kit_self_files()},
        "global": (build_global_section(global_dir) if include_global
                   else {"covered": False}),
    }


_HEX64 = re.compile(r"[0-9a-f]{64}")


def validate_baseline(data: object) -> dict:
    """The baseline, or ValueError naming the first problem.

    Every security field is required and typed. A loader that only checked for
    a JSON object turned missing keys into empty defaults: replacing the
    baseline with ``{}`` compared the surface against nothing and could read as
    OK, and an empty ``kit.files`` silently switched off the kit self-check.
    """
    def need(cond: bool, what: str) -> None:
        if not cond:
            raise ValueError(f"baseline {what}")

    need(isinstance(data, dict), "is not a JSON object")
    need(data.get("version") == BASELINE_VERSION,
         f"version {data.get('version')!r} is not the supported {BASELINE_VERSION} "
         "(re-bless after reviewing the hooks)")
    sh = data.get("settings_hooks_sha256")
    need(isinstance(sh, dict) and sh, "settings_hooks_sha256 is missing or empty")
    need(all(isinstance(k, str) and isinstance(v, str) and _HEX64.fullmatch(v)
             for k, v in sh.items()), "settings_hooks_sha256 holds a non-digest value")
    files = data.get("files")
    need(isinstance(files, list), "files is not a list")
    paths = set()
    for i, f in enumerate(files):
        need(isinstance(f, dict) and isinstance(f.get("path"), str) and f["path"],
             f"files[{i}] has no path")
        need(f["path"] not in paths, f"files[{i}] repeats {f['path']}")
        paths.add(f["path"])
        d = f.get("sha256")
        need(d is None or (isinstance(d, str) and _HEX64.fullmatch(d)),
             f"files[{i}] sha256 is not a digest")
        need(isinstance(f.get("events"), list) and all(isinstance(e, str) for e in f["events"]),
             f"files[{i}] events is not a list of strings")
        need("link" not in f or isinstance(f["link"], str), f"files[{i}] link is not a string")
        need("exec" not in f or isinstance(f["exec"], bool), f"files[{i}] exec is not true or false")
    bc = data.get("bytecode")
    need(isinstance(bc, dict) and all(isinstance(k, str) and isinstance(v, str)
                                      and _HEX64.fullmatch(v) for k, v in bc.items()),
         "bytecode is not a map of digests")
    kit = data.get("kit")
    need(isinstance(kit, dict) and isinstance(kit.get("files"), dict) and kit["files"],
         "kit.files is missing or empty (the kit self-check would be off)")
    need(all(isinstance(k, str) and isinstance(v, str) and _HEX64.fullmatch(v)
             for k, v in kit["files"].items()), "kit.files holds a non-digest value")
    for key in ("unregistered_on_disk", "extra_globs"):
        need(isinstance(data.get(key), list) and all(isinstance(x, str) for x in data[key]),
             f"{key} is not a list of strings")
    need(isinstance(data.get("generated"), str) and data["generated"],
         "generated is not a timestamp string")
    ext = data.get("external_unchecked")
    need(isinstance(ext, list), "external_unchecked is not a list")
    for i, e in enumerate(ext):
        need(isinstance(e, dict) and isinstance(e.get("event"), str)
             and isinstance(e.get("path"), str), f"external_unchecked[{i}] is not an "
             "{event, path} object")
    g = data.get("global")
    need(isinstance(g, dict) and isinstance(g.get("covered"), bool), "global section is malformed")
    if g["covered"]:
        need(g.get("settings_hooks_sha256") is None
             or isinstance(g.get("settings_hooks_sha256"), str),
             "global.settings_hooks_sha256 is not a digest or null")
        regs = g.get("registrations")
        need(isinstance(regs, list) and all(
            isinstance(r, dict) and isinstance(r.get("event"), str)
            and isinstance(r.get("command"), str) for r in regs),
             "global.registrations is not a list of {event, command}")
        gfiles = g.get("files")
        need(isinstance(gfiles, list) and all(
            isinstance(f, dict) and isinstance(f.get("path"), str)
            and isinstance(f.get("sha256"), str) for f in gfiles),
             "global.files is not a list of {path, sha256}")
        need(isinstance(g.get("unresolved_registrations", 0), int),
             "global.unresolved_registrations is not a number")
    return data


def load_baseline(path: Path) -> dict:
    return validate_baseline(json.loads(path.read_text(encoding="utf-8")))


def check(root: Path, baseline_path: Optional[Path] = None,
          settings: Optional[Sequence[Path]] = None,
          global_dir: Optional[Path] = None) -> dict:
    """Compare the surface now against the baseline.

    ``status``: clean | drift | no-baseline | error. modified / added / removed,
    a changed settings surface, changed bytecode and a changed kit drive
    ``drift``. Informational lists never do. Global findings are folded in under
    their own ``global_*`` keys and never touch ``status``.
    """
    baseline_path = baseline_path or root / BASELINE_REL
    out: dict = {"status": "clean", "modified": [], "added": [], "removed": [],
                 "settings_changed": [], "escalated": [], "kit_changed": [], "bytecode_changed": [],
                 "info_new_unregistered": [], "external_unchecked": [], "not_checked": []}
    try:
        is_dir = baseline_path.is_dir()
        is_file = baseline_path.is_file()
    except OSError as e:
        out["status"] = "error"
        out["error"] = f"cannot look at the baseline path {baseline_path}: {e.strerror or e}"
        return out
    if is_dir:
        out["status"] = "error"
        out["error"] = f"the baseline path {baseline_path} is a directory, not a file"
        return out
    if not is_file:
        out["status"] = "no-baseline"
        out["baseline_path"] = str(baseline_path)
        return out
    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError) as e:
        out["status"] = "error"
        out["error"] = f"baseline unreadable: {e}"
        return out
    try:
        surf = current_surface(root, settings, baseline.get("extra_globs") or ())
    except NotEvaluable as e:
        out["status"] = "error"
        out["error"] = str(e)
        # The surface could not be walked, but the files the baseline lists can still be
        # compared by hash: say which ones changed, so a tamper is not hidden by the error.
        changed = []
        for entry in baseline["files"]:
            try:
                p = root / entry["path"]
                if p.is_file() and entry.get("sha256") is not None \
                        and sha256_file(p) != entry["sha256"]:
                    changed.append(entry["path"])
            except OSError:
                pass
        if changed:
            out["error"] += ("; MODIFIED since bless: " + ", ".join(changed[:10])
                             + (f" and {len(changed) - 10} more" if len(changed) > 10 else ""))
        return out

    recorded_settings = baseline["settings_hooks_sha256"]
    empty = canonical_hooks_hash({})
    for label in sorted(set(recorded_settings) | set(surf["settings"])):
        if recorded_settings.get(label, empty) != surf["settings"].get(label, empty):
            out["settings_changed"].append(label)

    if isinstance(baseline.get("trust"), dict):
        out["escalated"] = escalations(baseline["trust"], trust_snapshot(root, settings))
    else:
        out["not_checked"].append("trust settings (defaultMode, allow rules, "
                                  "enableAllProjectMcpServers) are not pinned in this baseline: "
                                  "re-bless to start watching them")

    listed = {e["path"]: e for e in baseline["files"]}
    for rel, entry in sorted(listed.items()):
        path = root / rel
        if len(rel) > 4096 or any(len(part) > 255 for part in rel.split("/")):
            out["status"] = "error"
            out["error"] = (f"a baseline path is too long to be a file name "
                            f"({len(rel)} characters: {rel[:40]!r}...); the baseline is corrupt")
            return out
        try:
            present = path.is_file()
        except OSError as e:
            out["status"] = "error"
            out["error"] = f"cannot look at {rel[:200]} named by the baseline: {e.strerror or e}"
            return out
        if not present:
            out["removed"].append(rel)
            continue
        try:
            digest = sha256_file(path)
        except OSError as e:
            out["status"] = "error"
            out["error"] = f"cannot read {rel} to compare it with the baseline: {e}"
            return out
        link = os.readlink(path) if path.is_symlink() else None
        mode = _exec_bit(path)
        if (entry.get("sha256") is None or digest != entry["sha256"] or entry.get("link") != link
                or ("exec" in entry and mode is not None and entry["exec"] != mode)):
            out["modified"].append(rel)
    for rel in sorted(set(surf["entries"]) - set(listed)):
        out["added"].append(rel)

    rec_bc = baseline["bytecode"]
    for rel, cur in sorted(surf["bytecode"].items()):
        if cur["verdict"] == "mismatch":
            out["bytecode_changed"].append(
                f"{rel}: compiled code that does not match its source, and this "
                "interpreter would load it instead of the source")
        elif cur["verdict"] == "foreign":
            if rel not in rec_bc:
                out["not_checked"].append(
                    f"bytecode {rel} (Python tag {cur['tag']}) appeared after bless; this "
                    "interpreter cannot compare it with its source. Delete it, or run "
                    "hooks with `python3 -B`")
            elif rec_bc[rel] != cur["payload"]:
                out["bytecode_changed"].append(
                    f"{rel}: bytecode for another interpreter changed since bless and "
                    "cannot be compared with its source")

    rec_kit = baseline["kit"]["files"]          # validated: non-empty
    cur_kit = kit_self_files()
    for name in sorted(set(rec_kit) | set(cur_kit)):
        if rec_kit.get(name) != cur_kit.get(name):
            out["kit_changed"].append(name)
    out["kit_changed"] += [f"{b} (bytecode does not match its source)"
                           for b in kit_bytecode_mismatches()]

    known_unreg = set(baseline.get("unregistered_on_disk", []))
    for rel in on_disk_hook_scripts(root):
        if rel not in listed and rel not in surf["entries"] and rel not in known_unreg:
            out["info_new_unregistered"].append(rel)
    out["external_unchecked"] = [f"[{ev}] {p}" for ev, p in surf["external"]]
    out["not_checked"] = surf["not_checked"] + out["not_checked"]

    if (out["modified"] or out["added"] or out["removed"] or out["settings_changed"]
            or out["escalated"] or out["kit_changed"] or out["bytecode_changed"]):
        out["status"] = "drift"
    out.update(check_global(baseline, global_dir))
    recorded_global = baseline.get("global")
    covered = isinstance(recorded_global, dict) and recorded_global.get("covered") is True
    out["not_checked"] += out_of_scope_notes(global_dir, covered)
    return out


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _printable(findings: dict) -> dict:
    """A file name or command is data. Escape its control characters, so a name cannot erase a
    report line on a terminal or start a new line in the model's context."""
    def clean(v):
        if isinstance(v, str):
            return _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", v)
        return [clean(x) for x in v] if isinstance(v, list) else v
    return {k: clean(v) for k, v in findings.items()}


def render_report(findings: dict) -> str:
    """Human-readable report (``verify`` and the session-start hook share it)."""
    status = findings["status"]
    findings = _printable(findings)
    if status == "no-baseline":
        return ("hook-integrity: NOT EVALUABLE - no baseline yet. Review the hooks this "
                "project registers, then run `hook-integrity-kit bless`.")
    if status == "error":
        return f"hook-integrity: NOT EVALUABLE - {findings.get('error')}"

    lines: List[str] = []
    if status == "clean":
        gaps = len(findings.get("external_unchecked", [])) + len(findings.get("not_checked", []))
        lines.append("hook-integrity: OK - the hook surface matches the baseline"
                     + (f"; {gaps} NOT CHECKED below" if gaps else ""))
    else:
        lines.append("hook-integrity: DRIFT - the hook surface no longer matches the baseline:")
        lines += [f"  x MODIFIED   {r}" for r in findings["modified"]]
        lines += [f"  x ADDED      {r} (registered or imported, not in the baseline)"
                  for r in findings["added"]]
        lines += [f"  x REMOVED    {r} (in the baseline, missing on disk)"
                  for r in findings["removed"]]
        lines += [f"  x SETTINGS   `hooks` block, `env` block, hook-control key or command setting changed in {r}"
                  for r in findings["settings_changed"]]
        lines += [f"  x ESCALATED  {r}" for r in findings.get("escalated", [])]
        lines += [f"  x BYTECODE   {r}" for r in findings.get("bytecode_changed", [])]
        lines += [f"  x KIT        the kit's own code changed: {r} (upgraded? re-bless)"
                  for r in findings["kit_changed"]]
    lines += [f"  . info: new unregistered hook file on disk: {r}"
              for r in findings.get("info_new_unregistered", [])]
    lines += [f"  . NOT CHECKED: {r} is registered by absolute path outside the project"
              for r in findings.get("external_unchecked", [])]
    lines += [f"  . NOT CHECKED: {r}" for r in findings.get("not_checked", [])]

    g = findings.get("global_status")
    n = findings.get("global_registration_count", 0)
    if g == "drift":
        lines.append(f"  ! GLOBAL ~/.claude surface changed (warn-only; {n} registration(s) live):")
        lines += [f"      {c}" for c in findings.get("global_changes", [])]
        lines.append("      Benign if you just installed or updated a tool: review, then "
                     "re-bless with --include-global. If not, inspect before continuing.")
    elif g == "not-covered":
        lines.append("  . global ~/.claude surface: not in this baseline "
                     "(re-bless with --include-global to adopt)")
    elif g == "clean" and n:
        lines.append(f"  . global ~/.claude hooks: {n} registration(s), unchanged")

    if status == "drift":
        lines.append("If YOU made these changes: review the diff, then run "
                     "`hook-integrity-kit bless`.\nIf you did NOT: treat this as a possible "
                     "hook-injection compromise and inspect the files before running anything else.")
    return "\n".join(lines)
