# Changelog

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
