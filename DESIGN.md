# How hook-integrity-kit was built

This page explains why the kit exists, the contract it was built against, and how it was
hardened. If you only want to use it, the [README](README.md) is enough. The review history
near the bottom is for readers who want to see what independent review found.

## Why it exists

Project files have already carried code execution into Claude Code. Check Point
Research reported three such bugs ([write-up][checkpoint]):

- Hooks in a repository's `.claude/settings.json` ran when the project was opened
  ([GHSA-ph6w-f82w-28w6], fixed in 1.0.87).
- Project MCP settings could start commands before the trust dialog
  ([CVE-2025-59536], fixed in 1.0.111).
- A project `ANTHROPIC_BASE_URL` could send the API key elsewhere before trust was
  granted ([CVE-2026-21852], fixed in 2.0.65).

Those bugs are fixed, but the class remains. Once you trust a project, its hooks
run with your permissions, and edits to them are picked up without a restart.
Nothing tells you when:

- a pull, a merge or a dependency's install script changes a hook script;
- an agent edits or adds a hook in the middle of a session;
- a helper module that a hook imports changes while the hook file itself does not;
- `settings.local.json`, which is not committed and rarely reviewed, gains a
  `hooks` block.

## The contract it was built against

1. **Name every change** to what runs automatically, file by file, with exit 1.
2. **Never report clean when it could not look.** A missing or malformed baseline,
   an unreadable file and an unparsable hook all exit 2.
3. **Say what it does not cover on the run** (`NOT CHECKED` in `verify` and
   `bless`), not only in the docs, for every surface it can see. The classes it
   cannot see (helpers loaded by other languages, remote-managed settings, MDM and
   registry policy, `~/.claude.json`) are listed in `docs/coverage.md` instead.
4. **The agent cannot re-bless.** Blessing is a person's act after review.
5. **Standard library only, offline, deterministic.**

## Adversarial review rounds

Adversarial review rounds were run by separate AI sessions that had not written the code; each finding was reproduced against the source and pinned to a test before it was fixed. Every finding was fixed before the next
round.

| Round | Date | What it found |
|---|---|---|
| 1 | 2026-09-24 | The coverage model was narrower than the hook surface. An extensionless script could change unseen. A structurally invalid baseline read as clean. Symlink aliases bypassed the write protections. Documented destructive-command shapes slipped the guard. |
| 2 | 2026-09-25 | Helpers imported by plugin hooks were not baselined. Unchecked plugin handler types were missing from the report. |
| 3 | 2026-09-25 | The agent could re-bless through Bash (`bless`, or a redirect into the baseline). An unreadable listed file crashed `verify`. The README overclaimed "everything that runs automatically". The frontmatter scan missed valid YAML shapes. |
| 4 | 2026-09-26 | An imported subpackage behind a directory symlink could change while `verify` exited 0. |
| 5 | 2026-10-15 | Pre-release review. At the start of this round 420 tests passed and every earlier finding was fixed. **Found and fixed:** the kit's own control variables (`DISABLED_HOOKS`, `HOOK_PROFILE`, `HOOK_KIT_*`) could be set in the settings `env` block without drift or a refusal. A non-UTF-8 hook payload crashed with exit 1 (now denied, exit 2). The `pipe-to-shell` guard missed `\| /bin/sh`, `\| env bash` and `perl`/`ruby`/`node`. Remote deletion of `main`/`master` was not blocked. A `..` path in the recursive-delete check was not normalised. Pinned in `tests/test_settings_controls.py`, `tests/test_hook_protocol_and_cli.py`, `tests/test_command_pipe_to_shell.py`, `tests/test_command_git.py` and `tests/test_command_destructive.py`. |
| 6 | 2026-10-15 | Guards were quadratic on padded commands; a hook that times out lets the call through. Rules made linear; work budget fails closed. Measured on a 128 KB command of one repeated token, before: `curl x \| ` 37 s, `rm -r ` over 300 s, `tee ` 11 s, `dd of=/dev/null ` 10 s, `sed -i ` 7 s, `curl ` 4 s (and `rm `, `>`, `git push origin `, `chmod -R ` over 15 s). After, re-measured after the round-2 review (46 padded shapes, five runs each, a loaded 16-core box): 45 under 0.1 s and the worst, `sed -i `, 0.12 s; the three deliberately over-budget shapes under 0.05 s. The reviewer measured the `chmod -R ` and `chown -R ` shapes at 0.14 to 0.15 s on their machine, so "under 0.1 s" does not hold everywhere; the test ceiling is 2 s per shape, and the cost stays linear (about 0.1 s per 128 KB). Pinned in `tests/test_command_work_budget.py`. |
| 7 | 2026-10-15 | Independent pre-release review of the documentation and the CLI. The README said non-Python helpers were named as `NOT CHECKED`; they are neither detected nor reported (corrected). `install` mixed prose into the JSON, so redirecting it corrupted a settings file (prose now on stderr). A small non-UTF-8 payload was refused as "over 1 MiB" (the reason is now stated truthfully), and a missing `--root` read as "no baseline yet". The work budget's refusal of benign heredocs, the machine-specific `install` snippet and the effect of `onFailure: block` when the interpreter is missing are now documented. Pinned in `tests/test_hook_protocol_and_cli.py`; the sdist now carries `tests/conftest.py`, and its tests pass from the unpacked sdist. |
| 8 | 2026-10-15 | Second pre-release review. **Found and fixed:** `NOT CHECKED` was claimed for every out-of-scope surface but the user plugin cache, user-level settings hooks without `--include-global` and managed settings files were never reported (they are now, when present, and the classes still never reported are named in `docs/coverage.md`). A guard crashed with exit 1 (non-blocking) on deeply nested input or a closed stdin (now exit 2). Non-UTF-8 refusal depended on the locale (stdin is now read as bytes). `pipe-to-shell` missed `\|&`, `2>&1 \|`, `A=1 bash` and wrappers (`nice`, `command`, `timeout`, `stdbuf`, `nohup`, `exec`, `busybox`, nested `env`) and `php`. `rules`/`profile` accepted a missing `--root`. Docs corrected (round 7 test count, round 6 timings, recovery from a bad interpreter path happens outside Claude Code). Pinned in `tests/test_hook_protocol_and_cli.py`, `tests/test_unchecked_surfaces.py` and `tests/test_command_pipe_to_shell.py`. |
| 9 | 2026-10-15 | Third pre-release review of the command guard. **Found and fixed:** `pipe-to-shell` was bypassed by a backslash-newline inside the command (and every other rule the same way), by `|` and a comment across lines, by clustered short options that take a value (`sudo -Eu root bash`, `env -iu A bash`), by quoted option values with spaces, by `sudo -s`/`-i`, `doas -s`, `su` and `runuser`/`pkexec`, and by a reader budget that failed OPEN (16 chained wrappers or assignments read as allowed; now `work-budget-exceeded`, 32 words). `HOOK_INTEGRITY_MANAGED_DIRS` and `HOOK_INTEGRITY_GLOBAL_DIR` could be set in the settings `env` and hid two `NOT CHECKED` lines (now pinned: refused by `check-write`, drift in `verify`). **False positives fixed:** interpreter options before the program (`python3 -u -m json.tool`, `node -p`, `perl -MJSON -e`, `ruby -rjson -e`, version flags, script paths) and `curl x \|\| bash install.sh` (`\|\|` is not a pipe). Added `rbash`, versioned shells, `$SHELL`. Decided and documented, not changed: `sh -c '...'` and `bash script.sh` after a pipe stay blocked; `chroot / sh`, `tee >(sh)` and abbreviated long options stay gaps (docs/limits.md). Worst padded 128 KB command measured at 0.10 s over 68 shapes. Pinned in `tests/test_command_shell_syntax.py`, `tests/test_command_pipe_to_shell.py`, `tests/test_command_work_budget.py` and `tests/test_settings_controls.py`. |
| 10 | 2026-10-15 | Fourth pre-release review of the command guard. **Found and fixed:** `echo x >\| .claude/hook-integrity.json` was allowed (the segment ended at the `\|` of `>\|`; `&>`, `>&` and `2>&1` are now read as redirects everywhere a command is segmented, and `>\|` is no longer a pipe in `pipe-to-shell`); `sed -Ei`, `sed -ri`, `sed --in-place=.b`, `perl -p -i -e 1` and `perl -e 1 -i` were allowed (options are now parsed per cluster and position, with the quotes respected); `source <(curl ...)`, `. <(curl ...)` and `bash -o pipefail <(curl ...)` were allowed (the value of `-o`/`-O`/`--rcfile`/`--init-file` is skipped); an escaped identifier quote in `psql -c "DELETE FROM \"Users\""` hid the DELETE; `runuser -u u -g g sh` was allowed; the backtick form of `sh -c "$(curl ...)"` and a pipe inside backticks were allowed. **Quoted and escaped spellings** (`bl\ess`, `r\m`, `"rm"`, `dd of="/dev/sda"`) are now read by every rule. **False positives fixed:** a backslash-newline was judged both raw and joined, so `su \<nl>-c cat`, `runuser \<nl>-u root cat` and `DROP TABLE IF \<nl>EXISTS t` were blocked (only the joined text is judged now; an escaped backslash before a newline is not a continuation), and `perl -MIO -e 1 FILE`, `perl -I lib -ne print FILE` and `sed -e -i FILE` were read as in-place edits of FILE. **Stated in `docs/limits.md`, not fixed:** a quoted string with blanks or operators is matched as written, ANSI-C quoting is not read, and a separator inside quotes ends the stretch searched by the redirect and file-verb checks. Worst padded 128 KB command measured at 0.18 s (1 MB: 1.5 s, linear) over 112 shapes. Three round 7 pins were rewritten with the separator inside quotes (`sed '-i;x' FILE`), because the unquoted form is two commands. Pinned in `tests/test_command_protected_files.py`, `tests/test_command_shell_syntax.py`, `tests/test_command_pipe_to_shell.py` and `tests/test_command_sql.py`. |
| 11 | 2026-10-15 | Fifth pre-release review. **Blocker found and fixed:** the registered hook command was `python -m hook_integrity_kit`; hooks run in the project directory and `-m` puts it first on `sys.path`, so a project-local `hook_integrity_kit/__main__.py` replaced every guard and `session-start` with code that exited 0, and `verify` and `bless` never saw it. The command is now `PYTHON -c` with a program that drops every non-absolute `sys.path` entry before importing the kit; tests run the exact registered command through `sh -c` in a project holding a shadow package and `json.py`, `re.py`, `os.py`, `argparse.py`, `hashlib.py` and require exit 2 on a dangerous payload (the old form exits 0 in the same test). `check-write` also refuses a package named like the kit outside `src/`. A `PYTHONPATH` naming the project still shadows; stated in THREAT_MODEL.md. **Also fixed:** allowlist verbs matched with `\b`, so `echo=1 <command>` read as an `echo`; `bless` printed only some `NOT CHECKED` lines while the docs said it printed all (it prints the `verify` list now); `rm -rf //usr`, `/./etc`, `/home//alice`, `/usr/./` and `rm --rec /`; `bash < <(curl ...)`, `bash<(curl ...)`, `bash <<< "$(curl ...)"`, `python3 <(curl ...)`; `>|` and `>&` onto a disk; `gsed -i`; `DELETE/**/FROM` and `-- WHERE` comments. **False positives fixed:** `echo 'DROP TABLE users;'`, `grep -rn 'DELETE FROM x' src/`, `git commit -m "... curl x | sh"`, a heredoc into `q.sql`, and coreutils `truncate file -s 0` read as SQL. **Stated in `docs/limits.md`, not fixed:** other commands' option abbreviations, an interpreter option with a value in front of `<(curl ...)`, `cat <(curl x) | bash`, MySQL `#` comments, a statement inside a SQL comment, `-m "$(cat <<EOF ...)"` commit messages. Worst padded 128 KB command measured at 0.17 s (1 MB: 1.3 s, linear) over 38 shapes. Pinned in `tests/test_shadow_package.py`, `tests/test_command_destructive.py`, `tests/test_command_pipe_to_shell.py`, `tests/test_command_sql.py`, `tests/test_command_shell_syntax.py`, `tests/test_commands.py` and `tests/test_manifest.py`. |
| 12 | 2026-10-15 | Sixth pre-release review, adversarial. **Blocker found and fixed:** `check-write` allowed `"disableAllHooks": true` (and `allowManagedHooksOnly`) in `.claude/settings.json`, `settings.local.json` or `~/.claude/settings.json`, which switches every hook off, and `verify` reported OK. The keys that switch hooks off or narrow them (`manifest.HOOK_CONTROL_KEYS`) are now part of the settings surface hash and of the `check-write` rule; the names could not be checked against the live documentation and docs/coverage.md says so. **Also fixed:** dynamic imports (`importlib`, `runpy`, `__import__`, `exec(compile(open(...)))`) verified clean with no `NOT CHECKED` line although the docs said "named per file"; a shell hook running another project script (`bash x.sh`, `python3 p.py`, `./x.sh`) left that helper unhashed (now followed, transitively, and what cannot be followed is named); hook paths with spaces, quotes or a leading `cd DIR &&` were split at the blank, `bless` printed MISSING and exited 0 (it now refuses, exit 2, unless `--allow-missing`); `sql-delete-without-where` accepted a `WHERE` anywhere else on the line (the statement is now its own quoted string up to its `;`); quoted values of git's global options hid `push --force`, `branch -D` and `clean -fd`; tracebacks with exit 1 (1 means drift) for an over-long baseline path and an unwritable baseline path; bad config entries were dropped silently (every command that loads the config now names them); the guard judged Bash only (documented, configurable: `commands.shell_tools`, `install --shell-tool`). **Nits fixed:** more steering env keys pinned; the baseline schema is as strict as documented; `git clean` dry runs pass; `git grep` patterns are data; `dd of=/dev/./null`; `git diff --output=` and `--ext-diff` excluded from the read-only allowlist; `kill` in every spelling of KILL at pid -1; `tee`/`cp`/`mv`/`shred`/`wipefs` onto a raw disk; `bash -lc "$(curl ...)"`; a `.git` file; `check-gate-config` through a symlink; I/O errors no longer called kit bugs; `install` refuses an unusable interpreter. **Stated, not fixed:** replacing the whole `.claude/` directory (`git reset --hard`, `rm -rf .claude`) swaps in a self-consistent older baseline (THREAT_MODEL.md); tools other than Bash; a Python hook that starts another script through `subprocess`. Pinned in `tests/test_settings_controls.py`, `tests/test_manifest_imports.py`, `tests/test_shell_hook_scripts.py`, `tests/test_baseline_file.py`, `tests/test_config.py`, `tests/test_command_sql.py`, `tests/test_command_git.py`, `tests/test_command_destructive.py` and `tests/test_manifest.py`. |

The tests are grouped by the behaviour they cover,
not by the round that found a defect, so each row above names the files that now hold
its pins. The 420 above is the count at the start of round 5 and not the current total. Tests passing at the end of round 7: 592. At the end of round 8: 692. At the end of round 9: 921. At the end of round 10: 1210. At the end of round 11: 1399. At the end of round 12: 1593.

Most real defects were the same shape: a path that **reported clean when it had
not looked**, or a surface the baseline did not reach. That is why the
`NOT CHECKED` list and exit code 2 carry the weight of the design.

## Deliberate non-goals

- **Prevention.** `session-start` runs alongside the hooks it checks. Run
  `verify` from a shell or CI before opening an untrusted checkout.
- **A sandbox.** The shell guards match text. They are a seatbelt for the common
  accident, not a defence against a determined agent.
- **Automatic re-blessing.** It would bless a malicious mid-session edit.

## Credits in full

**Original to this project:** the hook-surface baseline and its honest states (a
registered-but-missing script, pre-coverage, unresolved and out-of-project
registrations are never reported clean), the import-walk coverage of helpers that
registered hooks load, warn-only global coverage, the settings-hooks write rule,
the argument-aware `rm`/`chmod`/`git push` rules, the unenforceable-disable report,
and the test suite.

- **[everything-claude-code (ECC)]** by Affaan Mustafa, MIT License. The MIT notice
  is reproduced in [NOTICE](NOTICE).
  - *Adapted* from `scripts/hooks/config-protection.js`: the "do not weaken the
    gate" hook itself, its protected-basename list, first-time creation allowed,
    `pyproject.toml` excluded, case-insensitive matching, `lstat`-based existence,
    and refusing a truncated payload.
  - *Follows the vocabulary of* `scripts/lib/hook-flags.js`: the
    `minimal`/`standard`/`strict` hook profiles and a disabled-hooks list. The tier
    table and the unenforceable-disable report are ours.
- **Check Point Research** (Aviv Donenfeld, Oded Vanunu), [RCE and API token
  exfiltration through Claude Code project files][checkpoint]: the threat this kit
  is built around (*inspired by*).
- **Anthropic, [Claude Code hooks reference][hooks]**: the hook input and output
  contract the guards implement.
- **[cc-safety-net]** (MIT) is a deeper, independent destructive-command guard;
  listed as related work, no code taken.

[everything-claude-code (ECC)]: https://github.com/affaan-m/ECC
[checkpoint]: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
[GHSA-ph6w-f82w-28w6]: https://github.com/advisories/GHSA-ph6w-f82w-28w6
[CVE-2025-59536]: https://github.com/advisories/GHSA-4fgq-fpq9-mr3g
[CVE-2026-21852]: https://github.com/advisories/GHSA-jh7p-qr78-84p7
[hooks]: https://code.claude.com/docs/en/hooks
[cc-safety-net]: https://github.com/kenryu42/cc-safety-net

Round 13 modelled the shell (a wrapper table, option families, a line-sequential `cd` model). A
fresh review broke it three ways (clustered wrapper options, `cd` in pipelines, subshells, functions
and heredocs), and the model cannot converge: each shell construct has endless spellings.
Round 14 replaced it with a conservative linear rule: read the script as words and raw text, take
the project root, the script directory and every literal directory after `cd`/`pushd`/`-C`/`--chdir`/
`CDPATH=`/`PATH=` as candidates, hash every word or path-like substring that names a project file
under one of them, follow shell scripts the same way, name what is not modelled, key state by path
under a work budget. The price is over-hashing (documented). At the end of round 13: 2000 tests.
2,265 tests at release.
