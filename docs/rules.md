# Rules, configuration and the hook protocol

## The default rules

`hook-integrity-kit rules` prints the active set. Every rule has a test that must
fire and a benign neighbour that must not.

**`check-command`** (Bash). Rules match the whole command, so `bash -c "..."` and
`$(...)` payloads are seen. A backslash-newline is joined first and only the joined
text is judged. The text is also judged with the quotes and backslash escapes removed
from each plain word (`r\m`, `"rm"`, `of="/dev/sda"`); a quoted string that holds
blanks or operators is matched as written. A read-only allowlist (`git status/log/diff`, `ls`,
`cat`, `echo`; each a whole word, and not with `--output`, `--ext-diff` or `--textconv`, so `echo=1 <command>`, an assignment, is not an
`echo`) excuses a hit only when every chained command is read-only and there
is no substitution or redirection.

**Quoted data arguments.** A command that only names something dangerous is not
refused for it. When a rule hits and the allowlist does not excuse it, the line gets a
second look: if EVERY command on it takes data (`echo`, `grep`/`egrep`/`fgrep`:
their quoted strings; `git commit`: the quoted message after `-m`, `-am`,
`--message`, `--message=`; a heredoc body when its command is `cat` printing or
writing a `.sql`, `.md`, `.txt`, `.rst`, `.csv`, `.json`, `.yaml`, `.yml`, `.toml` or
`.log` file, or `git commit` reading its message from stdin; `ls`, `cat`, `head`,
`tail`, `wc` and `git status/log/diff` may stand beside them), that text is blanked
and the rules run again on what is left. So `echo 'DROP TABLE users;'`,
`grep -rn 'DELETE FROM x' src/`, `git commit -m "docs: curl x | sh"` and a heredoc
into `q.sql` are allowed, and `echo 'x' ; <command>`, `echo '...' | sh`,
`echo hi > ".claude/hook-integrity.json"` (a redirect target is never blanked),
`git commit -m "$(...)"` (a double-quoted string holding `$(`, `${` or a backtick),
an unquoted-delimiter heredoc holding `$(`, and a heredoc into a `.sh` file are not.
Any other command on the line, a quote that never closes, `$'..'`, a subshell, a
here-string, or a line over 100,000 characters leaves the original verdict.

| Rule | Blocks | Allows (example neighbour) |
|---|---|---|
| `rm-recursive-root-or-home` | `rm -r`/`-rf`/`--recursive` on `/`, `/*`, a top-level directory, `~`, `$HOME`, `/home/<user>`; `..`, `//` and `/./` are normalised first, so `rm -rf /tmp/../`, `rm -rf //usr`, `rm -rf /./etc`, `rm -rf /home//alice` and `rm -rf /usr/./` are read as the directory they name; an unambiguous abbreviation of `--recursive` counts (`--rec`, `--r`) | `rm -rf ./build`, `rm -rf ~/project/build`, `rm -rf ./build/../dist` |
| `rm-no-preserve-root` | `rm ... --no-preserve-root` and its abbreviations (`--no-pre`, `--n`) | `rm --nope x` |
| `git-force-push-protected-branch` | `--force`, `-f` or a `+` refspec to `main`/`master`, in any order; also a remote delete: `git push origin :main`, `--delete main`, `-d origin master`, `:refs/heads/main` | `--force-with-lease`, force to other branches, `git push origin :feature/x` |
| `git-delete-protected-branch` | a forced delete of `main`/`master`: `-D`, `-d -f`, `-Df`, `--delete --force`, with `-C dir` or `-c k=v` in front | `git branch -D feature/x`, `git branch -d main` (git itself refuses an unmerged branch) |
| `git-clean-force-directories` | `git clean -fd`, `-df`, `-f -d`, `--force -d`, with `-C dir` (also a quoted `-C "my repo"`) in front | `git clean -n -d`, `git clean -nfd`, `git clean -fd --dry-run`, `git clean -f`, `git clean -fX` |
| `pipe-to-shell` | `curl ... \| sh`, `wget ... \| sudo bash`, `bash <(curl ...)`, `bash < <(curl ...)`, `bash<(curl ...)`, `bash <<< "$(curl ...)"` (the same for `python`, `perl`, `ruby`, `node`, `php`), `bash -o pipefail <(curl ...)` (the value of `-o`, `-O`, `--rcfile`, `--init-file` is skipped), `source <(curl ...)` and `. <(curl ...)` where they start a command, `sh -c "$(curl ...)"` and its backtick form, a `curl ... \| sh` inside `$( )` or backticks, `curl ... \| python3`, with a path (`\| /bin/sh`), `|&`, a backslash-newline or a comment inside the command, or wrappers in front (`sudo`, `doas`, `env`, `nice`, `ionice`, `command`, `timeout`, `stdbuf`, `time`, `nohup`, `exec`, `busybox`, ... with their options, clustered (`sudo -Eu root bash`) or quoted (`sudo -p 'a b' sh`)); `sudo -s`/`-i`, `doas -s`, `su`, `runuser` (also `runuser -u USER -g GROUP sh`: the options after the user name are skipped), `pkexec` (they start a shell that reads stdin); `rbash`, `bash5`, `$SHELL` and quoted or escaped spellings (`"ba""sh"`, `b\ash`); `perl`/`ruby`/`node`/`php`/`python` when they read their program from stdin (no `-e`/`-c`/`-m`/`-p`/`-r`, no script path, no version flag). A command whose wrappers and options run past 32 words after the pipe is **denied** as `work-budget-exceeded`. `||` is an or-list, not a pipe. What is not covered: [docs/limits.md](limits.md) | `curl ... \| python3 -m json.tool`, `curl ... \| python3 -u -W ignore -m json.tool`, `curl ... \| node -e '...'`, `curl ... \| perl -MJSON -e 1`, `curl ... \| python3 script.py`, `curl -f x \|\| bash install.sh`, `curl ... -o file`, `diff <(curl a) <(curl b)`, `bash < input.txt`, `python3 -m json.tool < <(curl x)`, `curl x >\| sh` (`>\|` is a redirect; `sh` is a file name) |
| `disk-format` / `disk-dd-to-device` / `disk-write-to-device` / `disk-redirect-to-device` | `mkfs`, `mke2fs`, `mkdosfs`, `mkntfs`, `dd of=/dev/sdX`, `tee`, `cp`, `mv`, `install`, `shred`, `wipefs`, `blkdiscard`, `sfdisk`, `sgdisk` or `mkswap` naming a raw disk device, `> /dev/sda` and the other redirect operators onto a disk (`>\|`, `>&`, `&>`, `>>`, `2>\|`). Paths are normalised first: `//dev/sda`, `///dev/sda`, `/./dev/sda`, `/tmp/../dev/sda` and `/dev/../dev/sda` are `/dev/sda` | `dd of=./disk.img`, `dd of=/dev/./null`, `> /dev/null`, `>& /dev/null`, `cp image ./disk.img`, `cat /dev/sda \| head -c 512` |
| `chmod-777-recursive-or-root` | `chmod -R 777 <anything>`, `chmod 777 /` | `chmod -R 755`, `chmod 777 ./one.log` |
| `chown-recursive-root` | `chown -R <user> /`, `chown -R --reference=FILE /` | `chown -R alice ./project` |
| `fork-bomb`, `kill-all-processes` | `:(){ :\|:& };:`, `kill -9 -1` and the other spellings of KILL at pid `-1` (`-KILL`, `-SIGKILL`, `-s 9`, `-n 9`, `--signal=9`, `-9 -- -1`) | `kill -9 <pid>`, `kill -1`, `kill -TERM <pid>` |
| `kit-self-bless` | the kit's name (`hook-integrity-kit`, `hook_integrity_kit`) followed by the word `bless` in the same command: `hook-integrity-kit bless`, `python3 -m hook_integrity_kit bless`, and plain words spelled with quotes or escapes (`bl\ess`, `bl""ess`, `b'l'ess`, `"hook-integrity-kit" bless`). A person re-blesses after review; the agent must not | `hook-integrity-kit verify` |
| `kit-baseline-shell-write` | `hook-integrity.json` / `hook-integrity-kit.json` named after any of: the redirect operators `>`, `>>`, `>\|`, `&>`, `&>>`, `>&FILE`, `n>`, `n>>`, `n>\|`, `<>` (`>&N` and `>&-` only duplicate a descriptor and are not a write); the verbs `tee`, `cp`, `mv`, `ln`, `install`, `rsync`, `truncate`, `rm`, `dd`, `unlink`, `curl`, `wget`, `patch`, `tar -x`, `gawk -i inplace`, `git checkout`, `git restore`, `git archive -o` / `--output` and `git bundle create`; `find` with `-delete` or `-exec`; `sed` or `gsed` asked to edit in place (`-i`, `-i.bak`, any short-option cluster holding `i` such as `-Ei`, `-ni`, `-ri`, `--in-place[=SUFFIX]` and its abbreviations, in any position among the arguments) and `perl -i` (`-i[EXT]` in any cluster among the switches: `-pi`, `-lpi`, `-0pi`, `-p -i -e 1`, `-e 1 -i`). Quoted or escaped spellings of plain words are read as for `kit-self-bless`. Not covered: other programs that write files (`python3 -c`, `ed`, an editor), and `cp`, `mv` and the other verbs when a `;`, `&` or `\|` inside quotes sits between the verb and the file name (`cp 'a;b' f` hides `f`) | `cat` or `git diff`/`git add` of the baseline, `sed -n p`, `sed -e s/a/b/` and `perl -ne print` reading it |
| `kit-settings-link` | `ln` (hard or symbolic), `link` or `cp -l` naming a Claude Code settings file (a hard link is the same file under another name) | `ln -s .claude/hooks h`; `ln a b` on other files |
| `git-grep-pager-command` | `git grep -O CMD` / `--open-files-in-pager=CMD` where CMD is itself a blocked command line (for example a download piped into a shell) | `git grep -O less`, `git grep -O 'less -R'`, `git grep 'a \| sh' file` |
| `sql-drop-database`, `sql-drop-schema`, `sql-drop-table-unguarded`, `sql-truncate-table`, `sql-delete-without-where` | in shell commands (e.g. `psql -c`); a DELETE is judged inside its own statement: up to its `;`, the end of the quoted string it sits in, or (unquoted) the next separator, so neither a missing semicolon nor a `WHERE` elsewhere on the line (`... \| grep -i where`, `-U where`, a second `-c "SELECT 1 WHERE 1"`) changes the verdict. SQL comments are removed before the SQL rules read the text as well (the written text is read too, and either one can hit): `DELETE/**/FROM t`, `DROP /* x */ TABLE t` and `DELETE FROM t -- WHERE id = 1` are refused, and a `WHERE` inside a comment does not count. A bare `TRUNCATE name` is also coreutils' `truncate file -s 0`, so it counts only with SQL around it: `TRUNCATE TABLE` anywhere, or `TRUNCATE name` with a SQL client on the line (`psql`, `mysql`, `mariadb`, `sqlite3`, `sqlcmd`, `duckdb`, ...), in the text of a tool declared under `sql_tools`, or as a statement that ends like SQL (`TRUNCATE a, b;`, or a closing quote after the name). Backslashes in front of a quote character are removed first, so `psql -c "DELETE FROM \"Users\""`, a schema-qualified `\"public\".\"Users\"`, backtick-quoted names and mixed case are read; the table name is any run of letters, digits, `.`, `_` and quote characters | `DROP TABLE IF EXISTS`, `truncate -s 0 file`, `truncate file -s 0`, `DELETE ... WHERE` |

**Timing.** Claude Code treats a hook that times out as non-blocking, so the built-in
rules run in time linear in the command length (a command padded to 128 KB is judged
in well under a second). What cannot be bounded that way is capped by a work budget
(one verb invoked over 512 times, more than 64 pipes after one `curl`/`wget`, more than
32 words to read after one pipe to find the command it runs, or about 2 MB of argument
text to split), and a command over the budget is **denied**
(exit 2, rule `work-budget-exceeded`), never left to time out. Your own `extra_rules`
regexes are not covered: a pathological pattern can still be slow, so keep them
simple.

**False positive: benign prose over the budget.** The budget counts text, not intent.
`cat > notes.md <<EOF` followed by 600 lines that say "run git status then rm the
file" is denied (`more than 512 invocations of 'rm'`). The budget is not weakened for
this. Remedy: write documentation with the Write tool, not a shell heredoc, or split
it into smaller commands.

**`check-write`** (Write, Edit, MultiEdit, NotebookEdit). Blocks: `.env` files (not
`.env.example`/`.sample`/`.template`), `credentials.json`, `~/.aws/credentials`,
`.ssh/`, SSH private keys (not `.pub`), system directories (`/etc`, `/usr/bin`,
`/var/log`, ...; absolute paths only), **`.git/` internals** (`.git/hooks` and
`.git/config` run code on later git commands), the kit's own baseline and config,
a package or module named like the kit (`hook_integrity_kit/`, `hook_integrity_kit.py`)
anywhere but under a `src/` directory (defence in depth; see the hook command below),
and **any edit that changes a `hooks` block** in `.claude/settings*.json`, the `hooks` or `mcpServers` of a repo-local plugin (`.claude/plugins/**/hooks.json`, `plugin.json`) and the `mcpServers` of `.mcp.json`. The
settings rule computes the block (and the whole `env` block, as
`verify` does) before and after the edit, so permission and model edits
still work, and any `env` change is refused; content it cannot parse is refused. Notes only: edits to hook
scripts, and secret-shaped content. Optional per-agent write scopes (see below).

**`check-gate-config`** (Write, Edit, MultiEdit). Refuses modifying an EXISTING
linter/formatter/test config: ESLint, Prettier, Biome, Ruff, shellcheck, stylelint,
markdownlint, `pytest.ini`, `.importlinter`, `.flake8`, `mypy.ini`,
`.pre-commit-config.yaml`, and the other spellings those tools read (`.pytest.ini`, `tox.ini`,
`.coveragerc`, `.mypy.ini`, `.eslintignore`, ...). A hard link to one in the same directory or a parent
counts as that file. Creating one is allowed unless the same tool already has a config in that
directory or a parent up to the project root, including a section of `pyproject.toml`, `setup.cfg` or
`package.json`: a new file there can outrank the gate (`pytest.ini` beats `pyproject.toml`). A monorepo
that wants a second config asks a person, or uses the override. `pyproject.toml` and `setup.cfg` are
deliberately not protected (they mix metadata with lint config), and neither is `conftest.py`, which is
test code. Each is an open way to weaken a gate.

## Command-line options

- `--root DIR` (bless, verify, session-start, rules, profile): the project root.
  Default: the nearest ancestor holding `.claude/` or `.git`. A directory that does
  not exist exits 2 and says so (bless, verify, rules, profile); `session-start` reports it in the session context and still exits 0.
- `--baseline FILE` (bless, verify, session-start): the baseline file. Default
  `.claude/hook-integrity.json` under the root. A symlink is refused by `bless`.
- `--json` (bless, verify): machine-readable output instead of the report. Exit
  codes are unchanged. `session-start` accepts the flag and ignores it: its output
  is always the text report, because it is read by a model, not parsed.
- `--allow-missing` (bless): write the baseline although a registered script does not exist. Without
  it `bless` lists the MISSING files on stderr, writes nothing and exits 2.
- `--shell-tool NAME` (install, repeatable): also register `check-command` for this tool name
  (matcher `Bash|NAME`). The tool's input must carry the shell text in `command`; this is not verified
  for any tool but Bash. Also list the name in `commands.shell_tools`.
- `--python PATH` (install): the interpreter written into the snippet. Default: the
  one running `install`. An empty value, a path that is not an executable file, or a bare name
  not on `PATH` is refused (exit 64): a guard registered with it would fail every call. `install` prints only JSON on stdout, so it can be redirected.
  Each hook runs `PYTHON -c 'import os,sys;sys.path[:]=[p for p in sys.path if
  os.path.isabs(p)];from hook_integrity_kit.cli import main;sys.exit(main(["NAME"]))'`,
  not `PYTHON -m hook_integrity_kit NAME`. Claude Code runs hooks in the project
  directory and `-m` puts that directory first on `sys.path`, so a `hook_integrity_kit/`
  package (or a `json.py`) inside the project would run in place of the kit with every
  guard switched off. The program drops every `sys.path` entry that is not absolute
  (the working directory, and a relative `PYTHONPATH` entry, which Python has already
  made absolute by then, so a `PYTHONPATH` naming the project still shadows: see
  [THREAT_MODEL.md](../THREAT_MODEL.md)). A hook registered by hand as `python -m
  hook_integrity_kit ...` has the old hole; re-run `install` and replace it.
- Also: `--settings FILE` (repeatable), `--global-dir DIR`, `--include-global` (bless),
  `--config FILE` (guards, rules). `hook-integrity-kit <command> --help` lists them.

## Overrides and configuration

Operator overrides are environment variables read by the hook process, which an
agent's own Bash calls cannot set: `HOOK_KIT_ALLOW_HOOK_EDITS=1` (settings hooks
rule), `HOOK_KIT_GATE_CONFIG_OVERRIDE=1` (gate configs). `DISABLED_HOOKS=check-write`
switches a guard off; `HOOK_PROFILE=minimal|standard|strict` gates your own hooks
through `hook_integrity_kit.profile.should_run()`. The kit's guards run in every
profile. `HOOK_INTEGRITY_MANAGED_DIRS` and `HOOK_INTEGRITY_GLOBAL_DIR` (where `verify`
looks for managed settings and the user directory) are operator variables too. All of
every `env` key is pinned, these included: a `check-write` of the settings `env` block that
adds, changes or removes one is refused, and one already there is drift.

Project config, `.claude/hook-integrity-kit.json` (JSON, so no dependency on
`tomllib`):

```json
{
  "commands":    {"extra_rules": [{"id": "no-terraform-destroy", "pattern": "\\bterraform\\s+destroy\\b"}],
                  "disable": ["kill-all-processes"],
                  "protected_branches": ["main", "release"],
                  "sql_tools": {"mcp__db__query": "sql"},
                  "shell_tools": ["Bash", "PowerShell"]},
  "writes":      {"extra_block": [{"id": "migrations", "pattern": "/migrations/"}],
                  "agent_scopes": {"researcher": ["notes/**", "/tmp/scratch-*/**"]}},
  "gate_config": {"extra_protected": {"tox.ini": "test matrix"}},
  "integrity":   {"extra_files": ["policy/*.json"]},
  "profiles":    {"tiers": {"my_slow_linter": "strict"}}
}
```

A broken config never weakens the defaults: an unreadable file is ignored with a
warning, and so is every entry the kit will not use. Each such entry is named on stderr by
every command that loads the config (`bless`, `rules`, `profile`, `check-command`,
`check-write`, `check-gate-config`): a section that is not an object (`"commands": null`),
`extra_rules` that is not a list, a rule whose pattern is not a regex that compiles, a
`disable` that is a string, an id in `disable` that names no rule, an unknown top-level key.
`verify` does not load the config (it reads the `extra_files` globs the baseline recorded). The config is itself protected by `check-write` and hashed by `bless`.

The config arrives with a clone or a pull and is obeyed at once. So the rules that protect the kit stay
on whatever `disable` says: `kit-self-bless`, `kit-baseline-shell-write`, `kit-baseline`, `kit-config` and
`claude-settings-hooks`. To let a config switch them off, the operator sets
`HOOK_KIT_ALLOW_PROTECTION_OFF=1` in the environment Claude Code runs in. Any other rule can still be
disabled, and `audit` flags a config that does it.

Per-agent write scopes: an agent named in `agent_scopes` (matched on the payload's
`agent_type`, which Claude Code sets inside a subagent) may write only inside its
globs. Agents with no entry, and the main session, fall back to the global rules. An agent whose entry is
malformed may write nothing. Paths are read against `CLAUDE_PROJECT_DIR`; the agent's `cwd` counts as a
root only when that variable is unset or `cwd` is a linked worktree (a `.git` file).

## Exit codes, per command

`verify`:

| Code | Meaning |
|---|---|
| 0 | The hook surface matches the baseline |
| 1 | **Drift.** Something that runs automatically changed; each change is named |
| 2 | **Not evaluable.** No baseline, an unreadable baseline, settings file, plugin registration or hooked file, a hooked Python file that does not parse, or no project root. Never a pass |
| 64 | Usage error |

`bless`: 0 written, 2 the surface could not be read, the baseline path cannot be written
or is a directory, or a registered script is MISSING (without `--allow-missing`), 64 usage.
`install`: 0, or 64 for an unusable `--python` or tool name. `session-start`:
always 0 (it warns into the session context and never blocks a session). The
`check-*` hooks: 0 allow (optionally with a note for the model), 2 block.

## Hook protocol

The guards follow the PreToolUse contract in the [Claude Code hooks reference][hooks]:
a block prints `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
"permissionDecision": "deny", "permissionDecisionReason": ...}}` on stdout, writes
the same reason to stderr, and exits 2. Advice (a note that a file is a hook script,
a secret-shaped string in the content) exits 0 with `additionalContext`, because
exit 2 would block the call. An empty payload is allowed, since it holds no call to judge. Any other
payload that is not a JSON object is refused: a truncated one can still hold a command. Input is read up
to 32 MiB; anything larger is refused unread, so memory use stays bounded. A command over 4 MiB is refused
too, because judging it could outlast the hook's timeout.

**Claude Code's own failure handling.** A PreToolUse hook that times out, exits
with a code other than 0 or 2, or cannot start does NOT block the call by default.
`hook-integrity-kit install` therefore prints each guard with `"onFailure": "block"`
(Claude Code 2.1.295+), which turns every such failure into a refusal. Keep it when
you merge the snippet; without it, everything below is fail-closed only inside the
kit's own process.

**A guard that crashes fails CLOSED for the tools it guards.** If `check-command`
cannot judge a Bash call, or `check-write` a write, because of an internal error,
the call is refused with the error in the reason, since a crash an input can provoke
would otherwise be a bypass. An I/O error (a permission, a missing path) is worded as
the environment's fault, not a kit bug. Calls to tools a guard does not judge are allowed. If a
kit bug blocks real work, set `DISABLED_HOOKS=<guard>` in the environment Claude Code
starts in and report the bug.

[hooks]: https://code.claude.com/docs/en/hooks
