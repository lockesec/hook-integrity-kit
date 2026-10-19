# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report security issues **privately**, using GitHub's "Report a vulnerability"
button on this repository (Security → Advisories). Do not open a public issue for a
vulnerability.

Include what you found, how to reproduce it, and what you think the impact is. You
should get an acknowledgement within 7 days.

## What counts as a vulnerability here

- A way to make `verify` exit `0` while something in the covered surface changed:
  a registered script, a module or bytecode cache that Python would load for a
  hooked file, a plugin registration, a `hooks` block, an interpreter-steering
  `env` key or a hook-control key (`disableAllHooks`, `allowManagedHooksOnly`, ...), any file
  `bless` listed, or the kit's own code. The tool's promise is the list `bless` prints: a change
  to anything on it, or to the settings it pins, is named by `verify`. What a hook runs without
  naming a file is not on that list (see "What does not").
- A way to make `verify` report clean on a surface it could not read: a missing or
  unreadable baseline or settings file, a registered script that does not exist.
- A payload shape that makes a `check-*` guard allow a call its rules should block,
  **through the documented hook contract** (for example a field it fails to read,
  or a crash that fails open on attacker-controlled input).
- A way for an agent to switch a guard off from inside a session without the
  operator's environment variables.
- Crashes or catastrophic regex backtracking on crafted input of a reasonable size.

## What does not

- **Wording that evades the command guard.** Variables, aliases, encodings and
  interpreter calls are a documented limit of text matching (see the README and
  THREAT_MODEL.md). New *shapes* are welcome as ordinary issues or pull requests;
  please include a benign neighbour so the false-positive cost can be measured.
- **What a hook runs without naming a project file by a literal path**: a Makefile run by
  `make`, `package.json` scripts run by `npm run`, `.envrc`, a directory (`python3 tools`,
  `run-parts dir`, which are named `NOT CHECKED`), a program read from stdin (`python3 - <<EOF`),
  a name assembled at run time, a path whose `..` follows a symlink, code loaded through an
  environment variable (`PYTHONUSERBASE`, `NODE_PATH`, ...; named `NOT CHECKED` when set in the
  hook). List such files in `integrity.extra_files`; they are then pinned like any other.
- **Surfaces documented as out of scope**: installed plugins outside the project,
  scripts registered by absolute path outside the project, shell-level writes that
  `verify` reports afterwards, a baseline blessed without review, and every surface
  in [docs/coverage.md#not-covered](docs/coverage.md#not-covered). Most are
  named `NOT CHECKED` at run time when they exist; these are not reported: what a
  script written in a language other than Python and shell loads (for example the
  `require`s inside `helper.js`; the file a hook runs by a literal path, `node helper.js`,
  is hashed, but not what it loads), a Python hook starting another script through
  `subprocess`, the modules a shell hook's `python -m` or `-c` program loads (the program is named `NOT CHECKED`), any tool but Bash
  that runs shell text (unless configured: `commands.shell_tools`), a settings key
  that controls hooks under a name the kit does not list (`manifest.HOOK_CONTROL_KEYS`),
  remote-managed settings, MDM and registry policy, `~/.claude.json`, user-level
  skills and agents, and settings passed on the command line.

Writes through a hard link to a settings, baseline or config file are refused by
inode comparison within the searched directories (working directory and parents, project
directory, home); `ln`/`link`/`cp -l` on a settings file is refused in Bash.

The shell-hook follower no longer models the shell; every literal project file a
script names is hashed (over-hashing is the trade-off, documented in docs/coverage.md), and
unmodelled constructs are named `NOT CHECKED`. Bash writes to settings files are not refused and
are seen only by `verify` (README, docs/limits.md).
