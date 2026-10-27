# What each command does

| Part | What it checks or refuses |
|---|---|
| `verify --format jsonl`, `session-start --events FILE` | Findings as events for a SIEM: one JSON line per finding with severity and ATT&CK ids, and always a `RUN` event, so "checked, clean" and "could not look" are records ([events.md](events.md), with two Sigma rules) |
| `audit` | No baseline: lists what a checkout runs on its own (hooks, command settings, `.mcp.json`, VS Code folder-open tasks, devcontainer commands) and what it lets the agent do unasked, and flags dangerous commands, fetch-and-run hook scripts, folder-open tasks, `enableAllProjectMcpServers`, `bypassPermissions`, whole-tool and network-command allow rules, and `disableAllHooks` |
| `bless` / `verify` | The `hooks` block, interpreter-steering `env` keys and hook-control keys (`disableAllHooks`, `allowManagedHooksOnly`, ...) of `.claude/settings*.json`; the scripts registered there and by repo-local plugins; every project file a shell hook names by a literal path, followed transitively; what Python imports for a hooked Python file, resolved the way the interpreter does; their bytecode caches; the kit's own code; and any globs you list in `integrity.extra_files` |
| `session-start` | Runs `verify` at session start and warns into the session; exits 0 whatever it finds |
| `check-command` | `rm -rf` on root or home, force-push or forced delete of `main`, pipe-to-shell, raw-disk writes (`dd`, redirects, `tee`/`cp`/`mv`/`shred`/`wipefs` onto a device), `chmod -R 777`, SQL drops and unguarded deletes, and the agent re-blessing the baseline. Judges the Bash tool; list more in `commands.shell_tools` ([limits.md](limits.md#which-tools-are-judged)) |
| `check-write` | `.env`, credentials, SSH keys, system directories, `.git/` internals, the kit's baseline and config, and any edit that changes a `hooks` block, an interpreter-steering `env` key or a hook-control key such as `disableAllHooks` |
| `check-gate-config` | Edits to an existing linter, formatter or test config (creating one is allowed) |

`hook-integrity-kit rules` prints the active set with the severity of each rule. Every
rule ships with a test that must fire and a benign neighbour that must not (`rm -rf ~`
blocks, `rm -rf ~/project/build` does not), and `.claude/hook-integrity-kit.json` adds
your own rules, protected branches, write scopes per agent and extra files to pin
([rules.md](rules.md)).
