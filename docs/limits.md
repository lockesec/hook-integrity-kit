# Limits

## How well it works

- **Catch rate: not measured, and not what it measures.** It compares what a hook is now with what you reviewed. It does not judge whether a hook is malicious, so a hook that was bad when you blessed it reads as clean.
- **Attacks replayed: eight, with inert files.** Most are published; `hook-swap`, `helper-swap` and `hooks-disabled` are shapes with no public write-up. [attack-coverage.md](attack-coverage.md) shows what `audit` and `verify` report for each, and a test fails if the table and the code disagree. Eight replays are not a sample of real attacks.
- **Documented behaviour: checked by property tests** written from the docs (`tests/test_properties.py`, `python -m pytest`). They show agreement with the docs on what they cover, not that the docs are complete.

## Not tested

- Other teams' projects. It has been run on the author's own, including one with 63 hooks.
- Windows paths, beyond comparing settings names without regard to case.
- Whether Claude Code applies each pinned env key. The whole `env` block is pinned (name and value digest), and what each key does was not run; `audit` flags only the names known to steer code or traffic.

## Out of scope on purpose

- Preventing a hook from running. This reports; a sandbox prevents.
- Files outside the project, which differ per machine. They are named instead ([coverage.md](coverage.md#not-covered)).

## Known holes


- **It runs inside the thing it checks.** `session-start` is itself a hook. A
  malicious hook registered on the same event runs in parallel with it (the hooks
  reference: "All matching hooks run in parallel") and has
  already run by the time the warning appears; the check reports tampering, it does
  not prevent it. Run `hook-integrity-kit verify` from a shell or CI **before**
  opening an untrusted checkout to get a verdict from outside.
- **A baseline is only as good as the review behind `bless`.** A baseline that
  arrives with a clone is the author's claim, not yours; bless it yourself after
  reading the hooks.
- **Shell guards match text.** Variables (`T=/; rm -rf $T`), aliases, a script
  written to disk and run later, and interpreter APIs (`python -c` with
  `shutil.rmtree`) are not resolved. A backslash-newline is joined before judging, and
  only the joined text is judged (`echo \<newline>rm -rf /` is an `echo`; an escaped
  backslash before a newline is not a continuation). The rules also judge the command
  with quotes and backslash escapes removed from each plain word, so `r\m -rf /`,
  `"rm" -rf /`, `dd of="/dev/sda"` and `hook-integrity-kit bl\ess` are read as the
  words they spell. That is all: a quoted string that holds a blank or an operator is
  matched as written (`bash -c "\rm -rf /"` is not read; `bash -c "rm -rf /"` is), ANSI-C
  quoting (`$'rm'`), variables and globs (`/bi?/rm`) are not resolved, and a `;`, `&` or
  `|` inside quotes ends the stretch that the redirect and file-verb checks of
  `kit-baseline-shell-write` search (`cp 'a;b' f` hides `f`; `sed`/`perl` in-place
  editing is read with the quotes respected). Pattern guards are a seatbelt for the common
  accident; a determined agent needs a sandbox. For a deeper command guard, see
  [cc-safety-net].
- **The registered hook command does not import from the project directory, within
  limits.** `install` registers `PYTHON -c '<program>'` that removes every non-absolute
  `sys.path` entry before importing the kit, because `python -m` would import a
  `hook_integrity_kit/` package or a `json.py` planted in the project (hooks run in the
  project directory). Tests run the exact registered command in a project holding such
  files. Still trusted: any `PYTHONPATH` entry (relative entries are made absolute
  before the program runs, so `PYTHONPATH=.` or the project's absolute path shadows
  again; `PYTHONPATH` in a settings `env` block is drift and is refused by
  `check-write`, but one exported in the environment Claude Code starts in is yours),
  `.pth` files and `sitecustomize` in the interpreter's own environment, and the
  interpreter itself. An empty `PYTHONPATH` entry (a leading or trailing colon) counts as the
  working directory and Python makes it absolute before the program runs (measured on
  Python 3.14, Linux), so it shadows exactly like `PYTHONPATH=.`. `check-write` also refuses a package or module named like the
  kit outside a `src/` directory, which is defence in depth and not the fix. A hook
  registered by hand with `-m` keeps the hole.
- **Quoted data arguments are set aside only in the cases in
  [rules.md](rules.md#the-default-rules).** Still refused although they run nothing:
  a commit message given as `-m "$(cat <<'EOF' ... EOF)"` (a double-quoted `$(`), a
  heredoc into a `.sh`, `.py` or extensionless file, `printf`, `awk`, `sed -n '/x/p'`,
  `rg` (it has `--pre`, which runs a program), `git -C dir commit`, a quoted verb
  (`"echo" 'x'`), any other command on the same line (`grep x f | sort`), a statement
  inside a SQL comment (`/* DELETE FROM t */`), and a line over 100,000 characters.
  Text that only names a dangerous command, outside quotes, after `echo` is still
  excused by the read-only allowlist, as before.
- **SQL comments.** `/* ... */` and `-- ...` (the `--` followed by a blank) are
  removed; MySQL's `#` comments are not. A `/*! ... */` conditional comment is removed
  like any other although MySQL runs its contents (a statement written whole inside
  one is still read from the written text). An unclosed `/*` is left as written.
- **Long-option abbreviations** are read for `rm` (`--rec`, `--r`, `--no-pre`) and, with
  at least three letters, for `chmod` and `chown` `--recursive`. Other commands'
  abbreviations (`git push --del`, `sudo --us root bash`) are not.
- **Download redirected into a reader.** Covered: a shell or interpreter (`sh`, `bash`,
  `zsh`, ..., `python*`, `perl`, `ruby`, `node`, `php`), with its options, followed by
  `<(curl ...)`, `< <(curl ...)` or `<<< "$(curl ...)"` / `<<< $(curl ...)` / the
  backtick form. Not covered: an interpreter option that takes a value in front of the
  substitution (`python3 -W ignore <(curl x)`), a file (`curl -o f x; bash f`), a
  variable, and `bash -c "$(<(curl x))"`. A `curl` inside `<( )` followed by a pipe into a
  shell (`cat <(curl x) | bash`) is read as a pipe to a shell and blocked.
- **Pipe-to-shell is recognised, not proven.** A backslash-newline is joined before any
  rule is judged. After `curl`/`wget` and a pipe (`|` or `|&`; `||` is an or-list and
  `>|` is a redirect, neither is a pipe), the kit skips comments, a leading `NAME=value` and these wrappers with
  their options (clustered, like `sudo -Eu root`, and quoted, like `sudo -p 'a b'`):
  `sudo`, `doas`, `pkexec`, `env` (including `-S 'string'`), `nice`, `ionice`,
  `command`, `timeout`, `stdbuf`, `time`, `exec`, `nohup`, `setsid`, `busybox`,
  `toybox`, `unbuffer`, `builtin`. It then judges the command. A reader is: a shell
  (`sh`, `bash`, `zsh`, `dash`, `ksh`, `ash`, `csh`, `tcsh`, `fish`, `rbash`, versioned
  names such as `bash5`, and `$SHELL`/`${SHELL}`, with a path, quoted or escaped);
  `sudo -s`/`-i` or `doas -s` with no command after it; `su` and `runuser` without
  `-c` (with `-c STRING` the string is judged; `runuser -u USER COMMAND` judges
  COMMAND after skipping `-g`, `-G`, `-s` and their long forms); `pkexec` with no command; and `python*`, `perl`, `ruby`, `node`, `php`
  when they read their program from stdin: interpreter options are skipped, and a
  `-c`/`-m`/`-e`/`-p`/`-r` program, a version or help flag, or a script path means
  stdin is data and the pipe is allowed (`curl x | python3 -u -m json.tool`,
  `curl x | node app.js`). A line that starts with `|` continues the line above it
  (a shell rejects that line; the kit reads it as a pipe).
  Deliberately blocked although it may be harmless: a shell after a pipe whatever its
  arguments, including `sh -c 'echo hi'` and `bash script.sh`, because the shell
  inherits the download as stdin and the string or script may read and run it
  (`sh -c 'sh'`, `bash -c "$(cat)"`); and a `|` that is only text, inside a quoted
  string or a comment (`curl x # a | sh b`).
  Not covered: wrappers it does not know (`xargs`, `flock`, `chrt`, `taskset`,
  `unshare`, `chroot / sh`, a shell function or alias), other interpreters (`lua`, `awk`,
  `pwsh`, `deno`, `bun`, `Rscript`), process substitution as the reader (`tee >(sh)`),
  a reader that starts inside `( )`, `{ }`, `$( )` or backticks (`curl x | (sh)`),
  `eval "$(curl x)"`,
  `source`/`.` behind a wrapper (`builtin source <(curl x)`), a computed name
  (`${SHELL:-sh}`, `$0`), abbreviated long options (`sudo --us root bash`), ANSI-C
  quoting (`$'sh'`), options of a wrapper it does not list, the
  arguments that follow the user name in `su`, a download by something other than
  `curl`/`wget`, and a downloader split from its pipe by `;`, `&&`, `&` or a newline
  that is not followed by a line starting with `|`. A command that needs more than 32
  words read after one pipe to find what runs (long chains of wrappers, options and
  `NAME=value`), or strings nested more than 4 deep (`su -c "su -c ..."`), is denied
  as `work-budget-exceeded`, not allowed. The substitution forms covered are:
  `sh -c "$(curl x)"` and its backtick form (the `-c` may sit in a cluster, `bash -lc`, `-ec`, after other options, `sh -x -c`, or after an option value, `bash -o pipefail -c`), `bash [options] <(curl x)` with the value
  of `-o`/`-O`/`--rcfile`/`--init-file` skipped, `source <(curl x)` and `. <(curl x)` at
  the start of a command, and a `curl x | sh` inside `$( )` or backticks (a pipe is read
  wherever it is).
- **The work budget denies some benign prose.** A shell heredoc with more than 512
  mentions of one verb (for example hundreds of lines of documentation that say `rm`)
  is refused as `work-budget-exceeded`. Write documentation with the Write tool, not a
  shell heredoc. See [docs/rules.md](rules.md).
- **A WHERE belongs to its own statement.** `sql-delete-without-where` ends a DELETE at its
  `;`, at the end of the quoted string it sits in, or (outside any quote, or in a quote that
  never closes) at the next shell separator, quote or newline. A `WHERE` further along the
  line, in another argument, a pipe or a second `-c`, does not guard it. A heredoc body and
  the text of a `sql_tools` tool keep their newlines inside the statement. Reading is
  quote-pairing, not a SQL parser: a statement split across two quoted strings, or a quote
  character inside a SQL string literal that confuses the pairing, falls back to the strict
  reading (a few more refusals, never fewer).
- **Quoted values of git's global options** (`git -C "my repo" push -f ...`, `-c "a=b c"`,
  `--git-dir="x y"`, backslash-escaped blanks) are read as one word. The older
  whitespace reading is kept beside it for text that is itself inside a quoted string.
  `git push` and `git clean` rules still see only `git`'s own option letters: a value-taking
  option the kit does not list is a hole.
- **Dry runs.** `git clean` is not refused when `-n` is anywhere in a flag cluster or
  `--dry-run` (any abbreviation from `--d`) is given, unless a later `--no-dry-run` follows.
- **The read-only allowlist is not read-only for every option.** `git diff`, `git log` and
  `git show` accept `--output=FILE` (it writes a file) and `--ext-diff` / `--textconv` (they
  run a configured program), so a segment carrying one is not excused by the allowlist;
  `--output` aimed at the baseline is also a `kit-baseline-shell-write`. Other options of the
  allowlisted verbs that run programs through git configuration (a pager, an alias) are not
  read.
- **Replacing the baseline by replacing its directory.** The rules match the baseline by
  FILE NAME. `rm -rf .claude`, `mv .claude x`, `git checkout HEAD~1 -- .claude`, `git restore
  -s X .claude` and `git reset --hard` swap in an older, self-consistent `.claude/` (an old
  baseline with the old hooks) and are not matched; `verify` then reports clean, because
  what is on disk matches the baseline that came with it. Review `git diff` of `.claude/`
  and require review of baseline changes (code owners) as the THREAT_MODEL says. A missing
  baseline (a plain delete) is NOT EVALUABLE, not clean.
- **Raw disk writes.** `dd of=/dev/...` and any redirect onto a raw disk device are refused,
  and so are `tee`, `cp`, `mv`, `shred`, `wipefs`, `blkdiscard`, `sfdisk`, `sgdisk` and `mkswap`
  naming one (`/dev/sd*`, `hd*`, `vd*`, `xvd*`, `nvme*`, `mmcblk*`, `disk*`). Other writers
  (`parted`, `fdisk` scripted through stdin, `mkfs` is its own rule, an `ioctl` from Python)
  are not.
- **`kill`.** The KILL signal aimed at pid `-1` is refused in the spellings `-9`, `-KILL`,
  `-SIGKILL`, `-s 9`, `-s KILL`, `-n 9`, `--signal 9`, `--signal=KILL`, with or without `--`.
  Other signals at `-1` (`kill -TERM -1`) and `killall`/`pkill` are not.
- **Helpers loaded by other languages** (`node helper.js`, Ruby `require`, Perl `use`)
  are not detected and not reported; see [coverage.md](coverage.md#not-covered).
- **Installed plugins** (`~/.claude/plugins/...`) are outside the project; only
  repo-local `.claude/plugins/*` are hashed. `verify` and `bless` name the user
  plugin cache as `NOT CHECKED` when it exists (presence only). `--include-global`
  covers `~/.claude/settings.json` registrations, warn-only, and not plugins.
- **Managed settings and other user-level surfaces.** A managed-settings file at the
  documented locations is named `NOT CHECKED` when it exists and is never read.
  Remote-managed settings, MDM and registry policy, `~/.claude.json`, user-level
  skills and agents, settings passed with `--settings`, and a `CLAUDE_CONFIG_DIR`
  relocation are not looked at and not reported.
- **Scripts registered by absolute path outside the project** are listed as
  `NOT CHECKED`, not hashed, because the path is machine-specific.
- **Import resolution follows the path finder for the hook's own directory**, plus
  directories the hook adds to `sys.path` when their value can be worked out from
  the file alone. Imports that resolve elsewhere (installed packages, a `sys.path`
  change built from the environment or a function call) are named, not hashed; an attacker who can write your site-packages is outside the
  project. The kit parses hooks with its own interpreter: run it with the Python
  your hooks use, or a hook with newer syntax is NOT EVALUABLE (exit 2).
- **Bytecode.** A cache that the kit's interpreter would load is compared with its
  source exactly. A cache for another Python version can only be pinned at bless
  time; one that appears later is named, not judged. `python3 -B` in the hook
  command (or `PYTHONDONTWRITEBYTECODE=1`) keeps caches out of the hook directory.
- **Symlinks are resolved at check time.** `check-write` judges a path as written
  and as resolved, so a link to a protected file is refused, and a link loop is
  refused outright. A link swapped between the check and the write is a race the
  hook cannot close.
- **Platforms.** Developed and tested on Linux; the settings rule compares names
  case-insensitively for macOS and Windows filesystems, but Windows paths are not
  otherwise tested.
- **`--include-global` writes home-directory paths into the baseline.** Keep that
  baseline outside the repository (`--baseline ~/.local/state/...`).
- **A baseline at a custom path has half the protection.** `check-write` knows a baseline by its
  content, under any name. The shell rule knows only the default names, so `cp x ~/.local/state/b.json`
  is not refused. Add a `commands.extra_rules` entry for your path. Text a command only produces at run
  time (`patch -i d`, where the diff names the baseline) is not seen under any name.
- **A project virtualenv is named, not hashed.** When a hook runs from a project venv, its `.pth` files
  and `sitecustomize.py` run first, at every start. They differ per machine, so hashing them into a
  committed baseline would read as drift everywhere else. `verify` lists them as `NOT CHECKED`; read that
  list. Packages in the same site-packages are not listed.
- **A baseline is known by the first 4 KB of a `.json` file.** A copy padded past that, or under another
  suffix, is not refused. `verify` reads only the path it is given, so a copy changes nothing it checks.
- **A script outside the project is named only if its path can be read.** A `../` word anywhere in a
  shell hook is named, and an absolute word with a script suffix. `/abs/lib` with no suffix is not, because
  it looks like every system program. Named is not hashed: a change to that file prints nothing new.
- **What counts as a rule that runs anything.** Interpreters and shells, by name or path and with an option
  (`bash -c`), plus `env`, `xargs`, `sudo`, `npx`, `uvx`, `pip`, `pip install`, `uv`, `uv run`, and `npm`,
  `pnpm` or `yarn` with `run`, `install` or `exec`. Programs that reach a shell only through an option or a
  project file (`git`, `find`, `awk`, `tar`, `make`) are not counted, and reading them is on you. An allow
  rule with arguments shows in reports as its command word and a hash; read the settings file for the rest.
- **`agent_scopes` matches the agent's name exactly.** A name with different case has no scope and falls
  back to the global rules.
- **A write scope trusts a `.git` file.** The agent's `cwd` counts as a root when it holds one, because
  that marks a linked worktree. An agent that can create that file through the shell can move its scope.
- **Not refused, by design or for now.** `find / -delete` and `mv ~ /dev/null` are not matched by the
  `rm` rules. `check-write` does not refuse `.envrc`, `.mcp.json` or `.vscode/tasks.json`, though each can
  run code: `verify` hashes `.mcp.json`, `audit` lists `.mcp.json` and folder-open tasks, and nothing here
  reads `.envrc`.
- **A second config in a monorepo needs a person.** `check-gate-config` refuses a new config below one the
  same tool already has, because the nearer file wins for that directory. Use the override.
- **A symlinked plugin directory is named, not followed.** `verify` prints `NOT CHECKED`, and `audit`
  exits 2, because the hooks behind it were not read.

[cc-safety-net]: https://github.com/kenryu42/cc-safety-net

## Which tools are judged

`check-command` registers on the matcher `Bash` and judges only `tool_input.command` of the Bash tool. Claude Code has other tools that run shell text (PowerShell on Windows, possibly others); this kit has not verified their names or input shapes and does not guess at them: **a command run through any tool but Bash is not checked.** To widen it, name the tool in `commands.shell_tools` in `.claude/hook-integrity-kit.json` (the rules are then applied to that tool's `tool_input.command` string, if it has one) and register the guard for it with `install --shell-tool NAME`. `Bash` cannot be removed from the list. A tool whose input does not carry the text in `command` is not covered even when listed.

## Writes to settings files through Bash

`check-write` judges the Write and Edit tools. A Bash command that rewrites a settings file
(`jq ... > .claude/settings.json`, `sed -i`, `printf >`, `tee`, `python -c`, `cp`, `mv`) is
**not refused**: `check-command` does not parse what an arbitrary program writes. Only
`verify` sees the result, as a `SETTINGS` change. `"disableAllHooks": true` also switches off
the `session-start` check, so once it is set only a manual or CI `verify` catches it.

## Shell hooks: over-hashing and the unmodelled

The follower does not model the shell (see [coverage](coverage.md#how-shell-scripts-are-followed)).
It hashes every project file a hook script or settings command names, under the project root,
the script's directory or any literal directory after `cd`, `pushd`, `-C`, `--chdir`,
`CDPATH=`, `PATH=`. A data file a hook mentions is hashed too and shows as drift when it
changes (over-hashing is preferred to under-hashing). Named `NOT CHECKED`, once per script, and
never hashed: a script run by a computed path, `eval`, functions, globs, `python -m`/`-c`, and
the preload variables. Hard links are compared by inode against the settings files, the
baseline, the config, `.git/config` and `.env` in the working directory, its parents, the
project directory and the home directory; `.env.*`, `*.env` and other credential files are not
compared.

## Not seen

What `bless` lists is the coverage. A hook can run code without naming a project file by a
literal path; the kit does not see that code, and says so only where noted. Each line: the
shape, what the kit does, the remedy.

- `make`, `npm run`, `direnv` and similar: the Makefile, `package.json` or `.envrc` they read is
  not hashed. List it in `integrity.extra_files`.
- A directory run as a program (`python3 tools`, `run-parts hooks.d`): named `NOT CHECKED`
  ("runs a directory"); its contents are not hashed. List them in `integrity.extra_files`.
- A program read from stdin (`python3 - <<EOF`, `cat x.py | python3`): the program text is in the
  hook script, which is hashed; files it imports or opens are not.
- A name built at run time (`"$A$B"`, `$0.real`, `step$n`, `xargs` from computed input): named
  `NOT CHECKED` where the kit sees a variable or substitution in a path; otherwise not seen.
- A path whose `..` follows a symlink (`link/../real`) is resolved as written, not through the
  link.
- A glob or brace expansion without a slash or script suffix (`bash h?`, `bash h{1,2}`).
- Code loaded through an environment variable (`PYTHONUSERBASE`, `PYTHONHOME`, `NODE_PATH`,
  `LD_LIBRARY_PATH`, `LD_PRELOAD`, `PERL5LIB`, `RUBYLIB`, `GEM_PATH`, ...): named `NOT CHECKED`
  when the hook sets it; the files it loads are not hashed.
- A script the kit cannot split into shell words (an unbalanced quote): named `NOT CHECKED`; a
  quoted path in it is still read from the raw text where it is a path-like string.
- A relative path after a computed `cd` (`cd "$(dirname "$0")/.."; bash hooks/x.sh`) is tried only
  from the project root and the script's directory; the `cd` and the unplaced file are each named
  `NOT CHECKED`. Write the path from the project root or through `$CLAUDE_PROJECT_DIR`.
- A `sys.path` change outside the forms in docs/coverage.md (`sys.path[0:0] = [...]`, string
  concatenation, an f-string, `.as_posix()`, a name assigned in a loop or by a function call):
  named `NOT CHECKED`; the directory is not searched.
- An MCP server started through a shell or a runner (`bash -c "./bin/server"`, `uv run
  --directory srv python src/main.py`): named `NOT CHECKED` as naming no project file; the files
  it runs are not hashed. List them in `integrity.extra_files`.
- `audit` judges a hook command with the same rules as the `check-command` guard, so a command
  the guard allows (`sh -c 'wget -qO- URL | sh'` with the pipe inside the quoted string) is not
  flagged there either.
- Trust escalation compares with the baseline: settings that were already widened when you ran
  `bless` (`bypassPermissions` at bless time) are not reported until they widen further.
- A script a Python hook starts through `subprocess` or `os.system` is not followed or hashed. `verify` prints a
  `NOT CHECKED` line naming the hook, so a later change to that script prints nothing further.
- A non-Python, non-shell file a hook runs by literal path (`node helper.js`) is hashed and one
  `NOT CHECKED` line says what it loads is not followed; the files it loads are not named.
- A Bash payload whose `command` is not a string is allowed unjudged (Claude Code's Bash tool
  always sends a string).

- **A Python file over 1 MiB is not followed.** Hook code is small; parsing a huge file can outlast
  the session-start timeout. Past the limit the check reports NOT EVALUABLE, names the file, and
  lists any baseline file whose hash changed ("MODIFIED since bless"). `session-start` also stops
  itself after 20 seconds (`HOOK_INTEGRITY_SESSION_DEADLINE`, in seconds) and prints that it did
  not finish. On a platform without `SIGALRM` (Windows) only the size limit applies.
