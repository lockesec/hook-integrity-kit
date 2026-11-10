# Threat model

What `hook-integrity-kit` defends, against whom, and where it stops.

## The asset

The **auto-executing surface** of a Claude Code project: every command Claude Code
runs without asking, because a settings file or plugin registered it as a hook.
That is the `hooks` block of `.claude/settings.json` and
`.claude/settings.local.json` (with the whole `env` block), the
hook registrations of repo-local plugins, the scripts all of those name, and what
Python loads for those scripts. Hooks run with the developer's full user
permissions, on every session start and, for PreToolUse/PostToolUse, on every tool
call.

## The threat class

Code arrives in the auto-executing surface without a human deciding to run it.

Published instances (all fixed; the class remains):

| Advisory | What happened | Fixed in |
|---|---|---|
| [GHSA-ph6w-f82w-28w6] | Hooks in a repository's `.claude/settings.json` executed when the project was opened, without a sufficient startup warning | 1.0.87 |
| [CVE-2025-59536] (GHSA-4fgq-fpq9-mr3g) | Commands from project configuration (MCP servers) could run before the startup trust dialog | 1.0.111 |
| [CVE-2026-21852] (GHSA-jh7p-qr78-84p7) | A project-set `ANTHROPIC_BASE_URL` sent requests, including the API key, elsewhere before trust was confirmed | 2.0.65 |

Source: Check Point Research, [RCE and API token exfiltration through Claude Code
project files][checkpoint] (Aviv Donenfeld, Oded Vanunu; public 2026-02-25), and the
GitHub advisory database.

Since those fixes, Claude Code asks before trusting a folder. **After** a project is
trusted, the hooks reference states that hook edits in settings files are picked up
by a file watcher, and all matching hooks run in parallel. So the remaining routes
are changes to an already-trusted project:

1. **Upstream change**: a `git pull` or merge brings a modified hook script or a
   new registration, reviewed as ordinary code or not at all.
2. **Benign-then-malicious swap**: a hook that was fine when it was reviewed is
   replaced later under the same path. The registration line does not change.
3. **Helper swap**: the hook file is untouched, but what it loads changes: a
   module it imports, a bytecode cache Python prefers, a sibling package that
   shadows a standard-library name, a symlinked entry point retargeted so Python
   resolves imports from another directory, or an `env` key (`PYTHONPATH`,
   `BASH_ENV`, `LD_PRELOAD`, `OPENSSL_CONF`, `PIP_INDEX_URL`, ...) that redirects the interpreter or a tool.
4. **Agent edit**: the model, possibly steered by injected content, edits a hook
   script, adds a registration, or edits `settings.local.json`, which is usually
   not committed and rarely reviewed.
5. **Local tooling**: an installer adds hooks to `~/.claude/settings.json`, which
   run in every project.
6. **Guard weakening**: the agent edits a lint/test config, or this kit's own config,
   so a failing check passes.

## Scope

The kit vouches for **command hooks registered in the project's settings files and
by repo-local plugins (`hooks/hooks.json` at any depth, and `plugin.json` `hooks`),
the project files those commands run, and what Python loads for them from the
hook's own directory, bytecode caches included**. Non-command handler types
(`http`, `mcp_tool`, `prompt`, `agent`), hooks declared in skill or subagent
frontmatter (the file is hashed, the hooks in it are not parsed), the scripts that
command-bearing settings keys (`statusLine`, `apiKeyHelper`, ...; the setting itself is pinned) run, plugin MCP server configs and MCP servers
run from an installed package or a URL (the project's `.mcp.json` and the project files its
servers run are hashed), imports that
resolve outside the hook's directory, sourced shell files, commands that run no
project file, and scripts outside the repository are named as `NOT CHECKED` by
`verify` and `bless`, as are the installed-plugin cache, user-level settings hooks
(unless `--include-global` was used) and managed settings files, each when it
exists on the machine. Never reported: helpers loaded by other languages,
remote-managed settings, MDM and registry policy, `~/.claude.json`, user-level
skills and agents, and settings passed on the command line
([docs/coverage.md](docs/coverage.md#not-covered)). A handler's definition in
the hooks block is still pinned, so swapping one for another is drift; what an HTTP endpoint, MCP tool or
model does when called is not something a file hash can see.

## What the kit detects or prevents

| Route | Control | Kind |
|---|---|---|
| 1, 2, 3 | `verify` / `session-start`: SHA-256 of every registered script (settings and plugins, one resolver), whatever Python's path finder loads for a hooked Python file from its resolved directory (transitively), bytecode caches checked against source, symlinked entry points' targets, plugin registration files, and the canonical `hooks` block plus interpreter-steering `env` keys of both settings files | **Detect**, named per file |
| 4 (hook script) | `check-write` note ("re-bless after review") + `verify` drift | Detect |
| 4 (registration) | `check-write` refuses any Write/Edit/MultiEdit that changes a `hooks` block, any `env` key or a hook-control key (`disableAllHooks`, `allowManagedHooksOnly`, ...: they switch every hook off or narrow them), in a project settings file or in `~/.claude/settings.json`, including through a symlink or a differently cased name; `verify` hashes the same keys | **Prevent** (tool path only) + detect |
| 4 (self-bless) | `check-command` refuses `bless` (also in quoted or escaped spellings of plain words) and shell writes, links, restores or deletes of the baseline and kit config through the redirect operators `>`, `>>`, `>\|`, `&>`, `>&FILE`, `<>`, the verbs `tee cp mv ln install rsync truncate rm dd unlink` and `git checkout/restore`, `git diff --output=`, and `sed`/`perl` in-place editing, all matched by the baseline's FILE NAME (replacing the whole `.claude/` directory is not matched; see below); `check-write` refuses them through the write tools | Prevent (text match) |
| 4 (git internals) | `check-write` refuses writes under `.git/` (hooks, config) | Prevent (tool path only) |
| 5 | `bless --include-global`: `~/.claude` registrations and their scripts | Detect, **warn-only** |
| 6 | `check-gate-config`; `check-write` refuses the kit's config and baseline; `bless` hashes the config | Prevent (tool path) + detect |
| Destructive commands | `check-command` | Prevent the common accident |

## What it does NOT defend against

- **A malicious hook that runs before or alongside the check.** `session-start` is
  a hook too. Hooks on the same event run in parallel, so a malicious SessionStart
  hook has run by the time the warning is printed. The kit reports; it does not
  stop. Mitigation: run `hook-integrity-kit verify` from a terminal or in CI before
  starting Claude Code in a checkout you did not write.
- **A bad baseline.** `bless` records whatever is on disk. If a user blesses without
  reading, or a baseline arrives with a clone, the malicious state becomes "clean".
  `bless` prints every file it hashes and the changes since the previous baseline,
  so that the act is a review, but it cannot make the review happen.
- **An attacker who can write both the hook and the baseline** (for example a
  merged pull request that changes both). The baseline is a reviewable file, not a
  signature. Review baseline diffs like code; keep it under code-owner review.
- **Tampering with the kit itself.** The kit hashes its own source, so a swapped
  guard in the same environment shows as drift. An attacker who controls the Python
  environment or `PATH` can replace the verifier and its answer.
- **Shadowing the kit from inside the project.** Claude Code runs hooks in the project
  directory, and `python -m hook_integrity_kit` would import a `hook_integrity_kit/`
  package (or a `json.py`, `re.py`, `os.py`) found there before the installed kit; the
  planted code could exit 0 for every guard and for `session-start`, and `verify` and
  `bless` would never see it. The registered command is therefore
  `PYTHON -c '<program>'`, which drops every `sys.path` entry that is not absolute
  before importing the kit, and `os`/`sys` are already loaded when it starts. Tests run
  the exact registered command in a project holding such files and require the real
  guard to run. `check-write` also refuses to create a package or module named like the
  kit outside a `src/` directory. **Limits:** a `PYTHONPATH` entry is trusted in every
  spelling (Python makes a relative entry absolute before any program runs, so
  `PYTHONPATH=.`, an empty entry (a leading or trailing colon) or the project's absolute path shadows again; in a settings `env` block
  it is drift and `check-write` refuses it, but one set in the environment Claude Code
  was started in is the operator's), as are `.pth` files and `sitecustomize` in the
  interpreter's environment, named as `NOT CHECKED` when the hook uses a project virtualenv. A hook
  registered by hand with `-m` keeps the hole.
- **Shell-level writes.** The write guards see the Write/Edit/MultiEdit/NotebookEdit
  tools. `echo ... >> .claude/settings.json` through Bash is not a write-tool call;
  it is caught afterwards as drift, not prevented. The one shell write that would
  leave no drift, re-blessing or rewriting the baseline, is refused by
  `check-command`, by text match of the spellings listed in `docs/rules.md` (any
  other writer, such as `python3 -c`, `awk -i inplace` or an editor, is not matched,
  and a determined agent can evade the rest).
- **Replacing the baseline together with the hooks it vouches for.** `rm -rf .claude`,
  `mv .claude x`, `git checkout HEAD~1 -- .claude`, `git restore -s X .claude` and
  `git reset --hard` put back an older `.claude/` whose baseline matches its own hooks;
  `verify` reports clean. The guard matches the baseline by file name and these commands
  do not name it. They are ordinary developer commands, so they are documented here
  instead of refused: require review of `.claude/` diffs.
- **Tools other than Bash.** `check-command` judges the Bash tool's command. Another tool
  that runs shell text is not checked unless it is listed in `commands.shell_tools` and
  registered (`install --shell-tool`); the kit has not verified the names or input shapes of
  such tools and does not guess.
- **Semantic evasion of the command guard.** Variables, aliases, encoded payloads,
  scripts written and run later, and interpreter APIs are not resolved.
- **Things outside the project**: installed plugins under `~/.claude/plugins`
  (NOT CHECKED when the cache exists), managed settings files (NOT CHECKED when
  present), MCP server binaries, installed Python packages, and scripts registered
  by absolute path outside the project (NOT CHECKED). Remote-managed settings, MDM
  and registry policy and `~/.claude.json` are not looked at and not reported. The `permissions` block is
  deliberately not drift, so that ordinary changes do not train people to re-bless
  blindly. The whole `env` block IS pinned (a digest per key), because a list of
  names misses the tools nobody listed (`OPENSSL_CONF`, `PIP_INDEX_URL`,
  `ANTHROPIC_CUSTOM_HEADERS`); the price is that an innocent `env` edit such as
  `NODE_ENV` reads as drift and needs a re-bless. Whether Claude Code hands the
  settings `env` block to hook processes is not verified by this kit; it pins the
  block on the assumption that it may.
- **Hook types and locations beyond the scope above**: listed as NOT CHECKED where
  the kit can see them; the classes it cannot are named in
  [docs/coverage.md](docs/coverage.md#not-covered) and are not reported.
- **A symlink swapped between the write check and the write.** The guard resolves
  links when it runs; it cannot hold the filesystem still until the tool writes.

## Trust assumptions

1. The Python interpreter and the installed kit are trustworthy at the moment
   `verify` runs. The kit hashes its own `.py` files and checks its own bytecode
   caches for the running interpreter against that source; it cannot vouch for the
   interpreter itself or for site-packages.
2. The person who runs `bless` has reviewed the listed files.
3. The baseline is protected like code (committed, reviewed, not auto-regenerated).
4. Claude Code's documented hook contract holds: exit 2 or a `deny` decision blocks
   a PreToolUse call, and SessionStart stdout reaches the session context.
5. Operator overrides (`HOOK_KIT_*`, `HOOK_INTEGRITY_*`, `DISABLED_HOOKS`) are set in the environment
   Claude Code starts in. They are read by the hook process, which the agent's own
   Bash calls do not modify; an operator who exports them for a whole session has
   opened that door for the whole session.

## Design choices that follow

- **Warn, do not block, at session start.** A hook inside the repository cannot be
  an unbypassable gate, and a hard block would stop every session after each
  legitimate hook edit, which trains people to disable the check.
- **Never auto-bless.** An automatic rebuild would bless a mid-session edit before
  the next check could see it.
- **Absence is never clean.** No baseline, unreadable settings, a registered script
  that is missing, a baseline without global coverage, and registrations that
  resolve to no readable script are each reported as what they are.
- **Unrelated settings changes are not drift.** A check that fires on every
  permission tweak gets ignored.

[GHSA-ph6w-f82w-28w6]: https://github.com/advisories/GHSA-ph6w-f82w-28w6
[CVE-2025-59536]: https://github.com/advisories/GHSA-4fgq-fpq9-mr3g
[CVE-2026-21852]: https://github.com/advisories/GHSA-jh7p-qr78-84p7
[checkpoint]: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/

## Hard links, shell hooks and Bash writes

- Hard links: a hard link to a protected file defeats a path rule. `check-write` compares
  (device, inode) against the settings files, the baseline, the config, `.git/config` and `.env`
  found in the working directory (or `CLAUDE_PROJECT_DIR`, or the process directory when the
  payload has no `cwd`), its parents and the home directory, and `check-command` refuses linking
  a settings file. A file is never compared with itself, so a benign Edit of a settings file that
  has a second name elsewhere is allowed. `.env.*`, `*.env`, credentials and keys are covered by
  path rules only, not by inode. Links kept outside the searched directories are not seen.
- Shell hooks: the shell is not modelled. Every literal project file a script names is hashed
  under the candidate directories described in docs/coverage.md; a data file it mentions is hashed
  too (over-hashing, drift rather than silence). What is not modelled is named `NOT CHECKED`.
- Bash writes to settings files are not refused; `verify` is the only detector, and
  `disableAllHooks` also disables `session-start`.
- Import path: a `sys.path.insert` / `append` whose directory can be worked out from the file
  is followed (docs/coverage.md lists the forms); any other non-read use of `sys.path`-like
  objects is named `NOT CHECKED`.
