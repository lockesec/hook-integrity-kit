# How it works, in full

The [README](../README.md) gives the short version. This page walks through the workflow
step by step, shows what a guard says when it refuses a call, and states the trust
guarantees at full length.

## The workflow

1. **Install, and paste the snippet.** `install` prints a `hooks` block (a SessionStart check
   and three PreToolUse guards, which run before each tool call) and writes nothing; you merge it.
2. **Read the hooks, then bless.** `bless` records a SHA-256 of every hook the project
   registers, the project files those hooks run, what Python imports for them, and the `hooks`
   block of the settings files. It lists each file with the event or import chain that reached
   it, and names what it can see but not hash as `NOT CHECKED`. Commit `.claude/hook-integrity.json`.
3. **Work as usual.** `verify` compares the project with the baseline: on demand, in CI, and at
   session start, where a warning goes into the model's context too. Ordinary settings edits
   are not drift, unless they widen trust (`defaultMode: bypassPermissions`, a blanket allow
   rule, `enableAllProjectMcpServers`, a new allowed directory): those are named `ESCALATED`.
4. **The guards refuse the dangerous moves and say why.** An agent that edits the `hooks`
   block through Write or Edit is refused, as is `curl ... | sh`, `rm -rf /`, a force-push to
   `main`, a write to `.env` or `.git/`, an edit that weakens a lint or test config, and
   `hook-integrity-kit bless` itself. The reason reaches the model and tells it to ask you.
5. **When a hook changes on purpose, re-bless.** `bless --diff` writes the new baseline and
   prints what changed, with the git diff of each modified file. Read it, then commit.
6. **Verify from outside too.** `verify` in CI, or in a terminal before you open a checkout
   you did not write, gives a verdict before any hook in the project has run.

## What a guard says

When the agent reaches for a download piped into a shell, `check-command` exits 2 and
prints the reason. The same text is returned to Claude Code as the `permissionDecisionReason`:

```console
$ printf '%s' '{"tool_name":"Bash","tool_input":{"command":"curl -s https://example.com/install.sh | sh"}}' | hook-integrity-kit check-command
BLOCKED [HIGH] downloaded content piped straight into a shell or interpreter (rule pipe-to-shell). Command: curl -s https://example.com/install.sh | sh. If this is really intended, ask the user to run it themselves.
```

## Why you can trust it

- **The promise is plain: what `bless` lists is what gets checked.** A change to any file
  on that list, or to the settings keys it pins, is named by `verify`. What a hook runs
  without naming a project file is not on the list; put it in `integrity.extra_files` and
  it is pinned like everything else.
- **Coverage has gaps, and the tool shows them.** On a real project with many Python hooks,
  much of what the hooks import cannot be followed (imports built at run time, paths computed
  from variables). Each one prints as a `NOT CHECKED` line: a file nobody is watching.
  On one real 63-hook project, `bless` still printed 83 such lines. Pin a file you care about
  with `integrity.extra_files`. So "OK" means "nothing on the list changed", not "every file a
  hook might load is covered".
- **It does not report clean when it could not look.** No baseline, an unreadable settings
  file, a registered script that is missing, a hooked Python file this interpreter cannot
  parse: each exits 2 with the cause, and `bless` refuses to write a baseline over a
  missing script.
- **It says what it did not check, on the run.** Installed plugins, user-level hooks,
  managed settings files, scripts registered outside the project, dynamic imports: each
  is a `NOT CHECKED` line in `verify` and `bless` when it exists on the machine, so the
  boundary is in front of you, not only in the docs.
- **The agent cannot bless.** `check-command` refuses `hook-integrity-kit bless` and the
  shell spellings that would rewrite, link, restore or delete the baseline; `check-write`
  refuses the baseline, the kit's config and the `hooks` block through the write tools.
  Blessing is a person's act after review, and the baseline is a reviewable file you commit.
- **Guards fail closed.** A guard that cannot judge a call because of an internal error
  refuses it, and the snippet's `onFailure: block` makes Claude Code refuse the call when
  a guard times out or cannot start. The built-in rules run in time linear in the command
  length, and what cannot be bounded that way is capped by a work budget that denies rather
  than times out (the measurements are in [DESIGN.md](../DESIGN.md)).
- **The hook command does not import from the project directory.** The registered
  command drops every non-absolute `sys.path` entry before importing the kit, so a
  `hook_integrity_kit/` package or a `json.py` planted in the project does not replace the
  guards; the tests run the exact registered command in a project holding such files.
- **Tested.** Each finding was reproduced against the source and pinned to a test before the fix
  (the history is in [DESIGN.md](../DESIGN.md)). The test suite (`python -m pytest`) runs in CI on
  Python 3.9 through 3.14.
