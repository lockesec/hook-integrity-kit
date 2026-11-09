# Changelog

## Unreleased

Fixes found by a danger review:

- `check-write` also refuses an edit that adds or changes the hooks or MCP servers of a repo-local
  plugin (`hooks.json`, `plugin.json`) or `.mcp.json`, as it does for the settings `hooks` block.
- README no longer says "the agent cannot bless": the guards refuse the plain spellings, a
  determined agent can get around them, and the committed baseline is what review relies on.
- `session-start` can no longer run out of time in silence. A Python file over 1 MiB that a hook
  imports is not parsed: the check reports NOT EVALUABLE, names the file and lists any listed file
  whose hash changed. The check also stops itself after 20 s (`HOOK_INTEGRITY_SESSION_DEADLINE`
  overrides, in seconds) and prints that it did not finish, before the hook's 30 s timeout.
- `statusLine`, `apiKeyHelper` and the other command settings are now pinned by `bless`: adding or
  changing one is drift, and `check-write` refuses the edit. A skill or subagent file that declares
  hooks in its frontmatter is hashed, so a new one is ADDED and an edit is MODIFIED. The scripts
  those commands run are still not followed. Re-bless after upgrading if you use either.
- `audit` also reads `.devcontainer/<folder>/devcontainer.json`, which the devcontainer spec allows.
- A quote or heredoc opener in a shell comment, a delimiter such as `<<'A'B`, and every spelling of
  the `git grep` pager option can no longer blank a real command. A line with a comment gets no
  second chance.
- `bless` through `python -c` is refused, and so is `git push --mirror`.
- More env keys are pinned: Claude Code's own shell and config keys, `GLIBC_TUNABLES`, proxy and
  certificate settings. `enabledPlugins` and `extraKnownMarketplaces` are pinned too.
- `audit` lists execution env keys and plugin settings. `fileSuggestion` and `subagentStatusLine`
  are command settings.
- Control characters in a file name or command are escaped in the report.
- `audit` reads repo-local plugin hooks, follows what a hook reaches through scripts and imports, reads a
  continued shell line as one command, flags a config that disables rules, and names frontmatter hooks.
  A value of the wrong shape is named instead of ending the run.
- A config can no longer switch off the rules that protect the kit, unless the operator sets
  `HOOK_KIT_ALLOW_PROTECTION_OFF=1`.
- `check-write` knows a baseline by its content under any name. The shell rule also refuses `curl`,
  `wget`, `patch`, `tar -x`, `find -delete` and `gawk -i inplace` on the default names.
- `check-gate-config` protects more spellings and hard links, and refuses a new config that would sit
  beside or outrank one the same tool already has.
- A scoped agent can no longer widen its scope by moving its working directory, and a malformed scope
  lets that agent write nothing.
- A small payload that is not a JSON object is now refused, and so is a command over 4 MiB. Only empty
  input is allowed through.
- `verify` reports removed `deny` and `ask` rules, modes it cannot rank, and allow rules such as
  `Bash(python3:*)`, which run anything. An allow rule with arguments is stored as a hash, so a token in
  `settings.local.json` does not reach the committed baseline. `audit` hides secret env values, and
  events do not carry an `apiKeyHelper` command.
- A script a hook reaches outside the project (`. ../lib.sh`, `sh /abs/x.sh`) is named `NOT CHECKED`, and
  `verify`'s OK line counts what was not checked. `chmod -x` on a hashed hook is drift.
- `protected_branches` adds to `main` and `master` instead of replacing them. `bless` says when it
  replaces a baseline it could not read. A glob in a hook command is named, not recorded as a missing file.
- Property tests from the docs, run with Hypothesis. It is a test dependency only; nothing is added at
  install.
- Files beside a Python hook named like a standard-library module are hashed. A project virtualenv's
  `.pth` files, symlinked plugin directories and hooks that start other programs get a `NOT CHECKED` line.

## 0.1.0 (2026-10-19)

First public release. What it does:

**Baseline and check**
- `bless` records a SHA-256 baseline of the hooks a project registers (in settings files and
  repo-local plugins), the project files they run, what Python imports for them (resolved the
  way the interpreter does, including directories a hook adds with `sys.path.insert`), their
  bytecode caches, the project's `.mcp.json` and the files its servers run, and the kit's own
  code. `verify` names each change file by file and exits 1 on drift.
- Settings that widen trust (`bypassPermissions`, blanket allow rules,
  `enableAllProjectMcpServers`, new allowed directories) are named `ESCALATED`. The keys that
  switch hooks off or steer interpreters (`disableAllHooks`, `allowManagedHooksOnly`, `env`
  loaders) count as drift.
- `bless --diff` prints the git diff of each modified file since the commit that last wrote
  the baseline.
- What it cannot hash is printed as `NOT CHECKED` on every `verify` and `bless`. It cannot
  look, and says so, with exit 2 (`NOT EVALUABLE`), instead of reporting clean.
  On one real 63-hook project, following `sys.path.insert` took modules hashed from 22 to
  102 and `NOT CHECKED` notes from 131 to 83.
- `session-start` runs the check when a session opens and warns into the model's context.

**Audit, with no baseline**
- `audit` lists what a checkout runs on its own (hooks, command settings, `.mcp.json`
  servers, VS Code folder-open tasks, devcontainer commands) and flags dangerous commands,
  hook scripts that fetch and run code, and folder-open tasks. It replays the Mini Shai-Hulud
  pattern; on a real 46-item project it flagged nothing and noted three hooks that reach the
  network.
- An attack replay corpus covers eight published attacks with inert files.
  `docs/attack-coverage.md` is generated from those runs and a test keeps it current.

**Guards** (PreToolUse hooks that exit 2 to block)
- `check-command` judges Bash: `rm -rf` on root or home, force-push or deletion of `main`,
  pipe-to-shell (many spellings), raw-disk writes, `chmod -R 777`, risky SQL, and any attempt to
  re-bless or rewrite the baseline. It runs in time linear in the command and refuses what it
  cannot judge inside a fixed work budget.
- `check-write` refuses protected files, the baseline and config, writes through links to
  them, and edits that change a `hooks` block, a steering `env` key or a hook-control key.
- `check-gate-config` refuses edits that weaken an existing linter, formatter or test config.
- Every guard fails closed: unreadable, over-deep or non-UTF-8 input is refused. `install`
  prints each guard with `"onFailure": "block"` (Claude Code 2.1.295+).
- The registered hook command drops non-absolute `sys.path` entries before importing the kit,
  so a package planted in the project cannot replace the guards.

**Output and tooling**
- `--format jsonl` on `verify` and `audit`, and `session-start --events FILE`, write one JSON
  line per finding plus a `RUN` event, so "checked, clean" and "could not look" are both
  records ([docs/events.md](docs/events.md), with two Sigma rules written to the specification
  and not yet validated with sigma-cli).
- `rules` and `profile` show the active rules and hook profile. Custom rules, protected
  branches and extra pinned files go in `.claude/hook-integrity-kit.json`.
- Standard library only, Python 3.9 to 3.14. CI installs only hash-pinned dependencies and
  keeps no checkout token.

How the guards and the baseline were hardened, review by review, is in
[DESIGN.md](DESIGN.md#adversarial-review-rounds).
