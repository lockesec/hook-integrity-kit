"""``check-command``: refuse destructive shell commands before they run.

Registered as a PreToolUse hook on ``Bash``. Reads the hook payload, checks
``tool_input.command`` against the rules below, and denies on a hit.

How a command is judged (the order matters):

1. **Every rule is matched against the WHOLE command string**, quoted payloads
   included. That is what makes ``bash -c "..."``, ``sh -c '...'`` and
   ``$(...)`` payloads a non-gap: the dangerous text is still in the string.
2. Only then may the **read-only allowlist** excuse a hit, and only when the
   line holds no command substitution or redirection AND every chained command
   on it (split on ``;``, ``&&``, ``||``, ``|``, ``&``, newline) starts with an
   allowlisted read-only verb. This keeps ``git log --grep="rm -rf /"`` usable
   while ``echo hi; <anything>`` gets no free pass. An earlier design checked the
   allowlist first and returned "allow" at once, which exempted any command that
   merely STARTED with a safe verb from the entire blocklist.

The splitter is deliberately naive about quoting: a ``;`` inside quotes yields an
extra segment. That can only cause over-blocking, never under-blocking.

Rules come in two kinds. Most are regular expressions (case-insensitive).
Five are small argument parsers (``rm``, ``chmod``/``chown``, ``git push``,
``git branch`` deletion, ``git clean``),
because "recursive delete of the home directory" or "force push to main" depends
on which flags and which targets appear together in one invocation, in any
order, and a single regex for that is either unreadable or wrong.

Known limits, stated: this is pattern matching on text. Variables
(``T=/; rm -rf $T``), aliases, scripts written to disk and run later, and
interpreter APIs (``python -c "shutil.rmtree(...)"``) are not resolved. It is a
seatbelt for the common accident, not a sandbox.
"""
from __future__ import annotations

import bisect
import posixpath
import re
from dataclasses import dataclass, replace
from typing import Callable, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from . import config as cfgmod
from . import hookio


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    pattern: Optional[str] = None
    func: Optional[Callable[[str, "Context"], bool]] = None

    def hit(self, command: str, ctx: "Context") -> bool:
        if self.func is not None:
            return self.func(command, ctx)
        return re.search(self.pattern or r"(?!x)x", command, re.IGNORECASE) is not None


@dataclass(frozen=True)
class Context:
    protected_branches: Tuple[str, ...] = ("main", "master")
    #: The text is SQL by construction (a tool listed in ``commands.sql_tools``), not a
    #: shell command that may hold some: a bare ``TRUNCATE name`` is then a statement.
    sql_input: bool = False


# ── argument parsing helpers ────────────────────────────────────────────────

#: What ends a command: ``;``, a newline, ``&``, ``|``. A ``|`` or ``&`` that is part
#: of a redirect operator does not: ``>|``, ``&>``, ``&>>``, ``>&``, ``<&`` (and so
#: ``1>|``, ``2>&1``, ``<>``). ``|&`` is a pipe, and its ``|`` ends the command.
_BREAK = r"[;\n]|(?<![<>])&(?!>)|(?<!>)\|"
_SEP_RE = re.compile(_BREAK + r"|[`)]")

#: Work budget. Claude Code treats a hook that times out as non-blocking, so a
#: command padded to make a rule slow would be a way past every rule. The rules
#: below run in time linear in the command; what cannot be bounded that way is
#: capped here, and a command over a cap is REFUSED (``WorkBudgetExceeded``)
#: rather than left to time out. Honest commands are far inside every limit.
MAX_INVOCATIONS = 512        # one verb invoked this many times in one command
MAX_SCAN_CHARS = 2_000_000   # argument text one rule may split, summed over invocations
MAX_PIPES = 64               # pipes tried after the first curl/wget of one segment


class WorkBudgetExceeded(Exception):
    """The command is too large or too repetitive to judge in bounded time."""

    def __init__(self, what: str):
        super().__init__(what)
        self.what = what


def invocations(command: str, verb: str, quoted: bool = False) -> List[List[str]]:
    """Argument lists for every place ``verb`` is invoked in ``command``.

    A verb counts when it starts the line or follows whitespace, a separator,
    ``(``, a backtick or a quote, optionally with a path prefix (``/bin/rm``).
    Its arguments run to the next separator. Quote characters are stripped from
    each argument, so ``bash -c "rm -rf ~"`` yields ``['-rf', '~']``.

    Each invocation's arguments are the rest of its segment, so N invocations in
    one separator-free segment hold O(N * n) text. That is bounded by
    ``MAX_INVOCATIONS`` and ``MAX_SCAN_CHARS``; past either, ``WorkBudgetExceeded``.

    With ``quoted=True`` the arguments are read as shell words: a quoted or
    backslash-escaped value that holds blanks or a separator stays ONE argument
    (``git -C "my repo" push``, ``-c "a=b;c"``), and the invocation ends at the first
    separator OUTSIDE quotes. The plain reading above is kept beside it for text that
    is itself inside a quoted string (``bash -c "git -C \\"my repo\\" push"``).
    """
    out: List[List[str]] = []
    pat = re.compile(r"(?:^|(?<=[\s;&|(`'\"]))(?:[\w./-]*/)?" + re.escape(verb)
                     + r"(?=\s|$)")
    scanned = 0
    for m in pat.finditer(command):
        if len(out) >= MAX_INVOCATIONS:
            raise WorkBudgetExceeded(f"more than {MAX_INVOCATIONS} invocations of {verb!r}")
        if quoted:
            words, end = _command_words(command, m.end())
            scanned += end - m.end()
            if scanned > MAX_SCAN_CHARS:
                raise WorkBudgetExceeded(f"too much argument text after {verb!r}")
            # a word that STARTS with `#` opens a comment: nothing after it is an argument
            # (`git clean -fd # -n` is not a dry run)
            cut = next((k for k, w in enumerate(words) if command[w[0]:w[0] + 1] == "#"),
                       len(words))
            args = [w[2].strip("\"'") for w in words[:cut]]
        else:
            sep = _SEP_RE.search(command, m.end())
            end = sep.start() if sep else len(command)
            scanned += end - m.end()
            if scanned > MAX_SCAN_CHARS:
                raise WorkBudgetExceeded(f"too much argument text after {verb!r}")
            toks = command[m.end():end].split()
            cut = next((k for k, t in enumerate(toks) if t.startswith("#")), len(toks))
            args = [a.strip("\"'") for a in toks[:cut]]
        # A quoted empty word (`git -C "" push`) is still ONE word: dropping it would
        # leave `-C` taking `push` as its value and hide the subcommand.
        out.append(args if quoted else [a for a in args if a])
    return out


def git_invocations(command: str) -> List[List[str]]:
    """Every ``git`` invocation, read both ways (see ``invocations``): a rule hits
    when either reading shows the danger."""
    plain = invocations(command, "git")
    out = list(plain)
    readings = [command]
    if "\\" in command:                # text inside a double-quoted string: one level out
        readings.append(command.replace('\\"', '"').replace("\\'", "'"))
    for text in readings:
        out += [q for q in invocations(text, "git", quoted=True) if q not in out]
    return out


def _split_flags(args: Sequence[str]) -> Tuple[List[str], List[str]]:
    flags, operands, after_dd = [], [], False
    for a in args:
        if after_dd or not a.startswith("-") or a == "-":
            operands.append(a)
        elif a == "--":
            after_dd = True
        else:
            flags.append(a)
    return flags, operands


def _has_short(flags: Iterable[str], letters: str) -> bool:
    return any(f.startswith("-") and not f.startswith("--")
               and any(c in f[1:] for c in letters) for f in flags)


_HOME_WORDS = {"~", "$HOME", "${HOME}"}


_HOME_PREFIX = re.compile(r"(~[A-Za-z0-9._-]*|\$HOME|\$\{HOME\})(/.*)?$", re.DOTALL)


def _resolve_dotdot(t: str) -> str:
    """Collapse ``..`` and ``.`` segments (``/tmp/../`` is ``/``). A home prefix
    stands in as a one-level directory under ``/home`` so ``~/..`` lands on
    ``/home``. A target with no ``..`` segment is returned untouched."""
    if ".." not in t.split("/"):
        return t
    m = _HOME_PREFIX.match(t)
    if m:
        t = "/home/_home_" + (m.group(2) or "")
    if not t.startswith("/"):
        return t
    return posixpath.normpath(t)


def _collapse(t: str) -> str:
    """``//``, ``/./`` and a trailing ``/.`` mean what ``/`` means. An absolute path
    (or a home prefix followed by a path) is rebuilt from its non-empty, non-``.``
    segments; anything else, and a path that is already tidy, is returned as it was."""
    segs = t.split("/")
    if not any(s == "" or s == "." for s in segs[1:]) and not (segs[0] == "" and len(segs) > 1
                                                                 and segs[1] == ""):
        return t
    m = _HOME_PREFIX.match(t)
    if m:
        head, rest = m.group(1), m.group(2) or ""
        kept = [x for x in rest.split("/") if x not in ("", ".")]
        return head + ("/" + "/".join(kept) if kept else "")
    if not t.startswith("/"):
        return t
    kept = [x for x in segs if x not in ("", ".")]
    return "/" + "/".join(kept)


def is_root_or_home(target: str) -> bool:
    """True for the filesystem root, a top-level directory, or a home directory,
    in the spellings a shell accepts (trailing ``/``, ``/*``, ``/.``, ``//``,
    ``/./``, ``..``)."""
    t = _collapse(_resolve_dotdot(target.strip()))
    for suffix in ("/*", "/.", "/"):
        end = len(t)                    # an index, not repeated slicing: linear
        while end > 1 and t.endswith(suffix, 0, end):
            end -= len(suffix)
        t = t[:end] or "/"
    if t in ("", "/", "*", "/*") and target.strip() not in ("*",):
        return True
    if t in _HOME_WORDS or re.fullmatch(r"~[A-Za-z0-9._-]*", t):
        return True
    if re.fullmatch(r"/[^/*?]+", t):                     # /etc, /usr, /home, /tmp
        return True
    if re.fullmatch(r"/(?:home|Users)/[^/*?]+", t):       # /home/alice
        return True
    return False


# ── builtin rules ────────────────────────────────────────────────────────────

def _long_is(flags: Iterable[str], full: str, shortest: int) -> bool:
    """Is one of ``flags`` the long option ``--full``, or an abbreviation of it that
    GNU getopt accepts: a prefix of at least ``shortest`` letters (the shortest one
    that no other option of the same program shares), with or without ``=VALUE``?"""
    for f in flags:
        if f.startswith("--"):
            nm = f[2:].partition("=")[0]
            if len(nm) >= shortest and full.startswith(nm):
                return True
    return False


def _rm_root_or_home(command: str, ctx: Context) -> bool:
    for args in invocations(command, "rm"):
        flags, operands = _split_flags(args)
        recursive = _has_short(flags, "rR") or _long_is(flags, "recursive", 1)
        if recursive and any(is_root_or_home(o) for o in operands):
            return True
    return False


_MODE_777 = re.compile(r"^(?:0?777|(?:a|ugo)\+rwx)$")


def _chmod_777(command: str, ctx: Context) -> bool:
    """chmod 777 (or a+rwx) applied recursively, or to root/home/top-level."""
    for args in invocations(command, "chmod"):
        flags, operands = _split_flags(args)
        if not operands or not _MODE_777.match(operands[0]):
            continue
        recursive = _has_short(flags, "R") or _long_is(flags, "recursive", 3)
        if recursive or any(is_root_or_home(o) for o in operands[1:]):
            return True
    return False


def _chown_recursive_root(command: str, ctx: Context) -> bool:
    for args in invocations(command, "chown"):
        flags, operands = _split_flags(args)
        recursive = _has_short(flags, "R") or _long_is(flags, "recursive", 3)
        # With --reference=FILE the owner comes from FILE, so there is no OWNER
        # operand and every operand is a target. Skipping operands[0] regardless
        # let `chown -R --reference=f /` through.
        by_reference = any(f.startswith("--reference") for f in flags)
        targets = operands if by_reference else operands[1:]
        if recursive and any(is_root_or_home(o) for o in targets):
            return True
    return False


_GIT_OPTS_WITH_VALUE = ("-C", "-c", "--git-dir", "--work-tree", "--namespace")


def _git_sub_args(args: Sequence[str], sub: str) -> Optional[List[str]]:
    """The arguments after ``sub`` in ``git [-C dir] [-c k=v] ... sub ...``, or
    None when the invocation runs a different subcommand."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == sub:
            return list(args[i + 1:])
        if a in _GIT_OPTS_WITH_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return None                                      # another subcommand
    return None


def _git_push_args(args: Sequence[str]) -> Optional[List[str]]:
    """The arguments after ``push`` in a ``git [-C dir] [-c k=v] push ...``."""
    return _git_sub_args(args, "push")


def _git_delete_protected_branch(command: str, ctx: Context) -> bool:
    """A forced delete of a protected branch, in every spelling git accepts:
    ``-D``, ``-d -f``, ``-Df``, ``--delete --force``, with global options such
    as ``-C dir`` in front. The regex this replaced knew only ``git branch -D``."""
    branches = set(ctx.protected_branches)
    for args in git_invocations(command):
        rest = _git_sub_args(args, "branch")
        if rest is None:
            continue
        flags, operands = _split_flags(rest)
        big_d = any(f.startswith("-") and not f.startswith("--") and "D" in f[1:] for f in flags)
        delete = big_d or _has_short(flags, "d") or "--delete" in flags
        force = big_d or _has_short(flags, "f") or "--force" in flags
        if delete and force and any(o in branches for o in operands):
            return True
    return False


def _git_clean_force_directories(command: str, ctx: Context) -> bool:
    """``git clean`` forced (``-f``/``--force``) AND removing directories
    (``-d``), in any order or clustering, with global options in front. The
    regex this replaced required ``git`` and ``clean`` to be adjacent, so
    ``git -C . clean -fd`` went through."""
    for args in git_invocations(command):
        rest = _git_sub_args(args, "clean")
        if rest is None:
            continue
        flags, _ = _split_flags(rest)
        force = _has_short(flags, "f") or "--force" in flags
        dirs = _has_short(flags, "d")
        if force and dirs and not _dry_run(flags):
            return True
    return False


def _dry_run(flags: Sequence[str]) -> bool:
    """Does ``git clean`` end up a dry run? ``-n`` anywhere in a cluster, or ``--dry-run``
    (any abbreviation from ``--dry``... down to ``--d``), unless a later
    ``--no-dry-run`` (or its abbreviation from ``--no-d``) turns it off again."""
    dry = False
    for f in flags:
        if f.startswith("--"):
            nm = f[2:].partition("=")[0]
            if nm and "dry-run".startswith(nm):
                dry = True
            elif len(nm) >= 4 and "no-dry-run".startswith(nm):
                dry = False
        elif f.startswith("-") and "n" in f[1:]:
            dry = True
    return dry


def _branch_of(ref: str) -> str:
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def _git_force_push_protected(command: str, ctx: Context) -> bool:
    """A forced push that names a protected branch, in any argument order.

    Forced means ``--force``, ``-f`` (alone or in a flag cluster such as
    ``-fu``) or a ``+`` refspec. ``--force-with-lease`` and
    ``--force-if-includes`` are NOT treated as forced: they refuse to overwrite
    work the pusher has not seen, which is the safe way to rewrite a branch.
    A bare ``git push --force`` that names no branch is not judged: which branch
    it pushes depends on local config the hook cannot see.
    """
    branches = set(ctx.protected_branches)
    for args in git_invocations(command):
        rest = _git_push_args(args)
        if rest is None:
            continue
        flags, operands = _split_flags(rest)
        if ("--delete" in flags or _has_short(flags, "d")) and any(
                _branch_of(o) in branches for o in operands):
            return True
        # an empty source (`:name`) deletes the remote branch
        if any(o.startswith(":") and _branch_of(o[1:]) in branches for o in operands):
            return True
        forced = ("--force" in flags or _has_short(flags, "f")
                  or any(o.startswith("+") for o in operands))
        if not forced:
            continue
        for o in operands:
            ref = o.lstrip("+")
            dst = ref.split(":", 1)[1] if ":" in ref else ref
            dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
            if dst in branches:
                return True
    return False


# ── linear-time matchers ────────────────────────────────────────────────────
#
# A regex of the shape ``A[^SEP]*B`` rescans the rest of the segment from every
# A, which is quadratic on a command padded with A. A match exists exactly when
# B occurs, before the next separator, after SOME end of A; and the EARLIEST A
# end inside a segment dominates the later ones. So each rule below lists the A
# ends once and searches for B once per segment. An A end is a position in the
# whole command (``sed -i`` and ``git\s+restore`` can run across a separator or a
# newline, as the regexes they replace could), and its segment is the one it
# lands in. Verdicts are the regexes' own; tests/test_command_work_budget.py pins the
# shapes where the two could drift.

_I = re.IGNORECASE
_SEP = re.compile(_BREAK)


def _ends_of(pattern: "re.Pattern[str]", command: str) -> List[int]:
    return [m.end() for m in pattern.finditer(command)]


def _then_in_segment(command: str, ends: Iterable[int], then: "re.Pattern[str]") -> bool:
    """True when ``then`` occurs after one of ``ends`` and before the next
    ``;``, ``&``, ``|`` or newline. Only the first end of each segment is tried."""
    done_to = -1
    for e in sorted(ends):
        if e <= done_to:                     # this segment was already searched
            continue
        sep = _SEP.search(command, e)
        stop = sep.start() if sep else len(command)
        done_to = stop
        if then.search(command, e, stop):
            return True
    return False


_RM_WORD = re.compile(r"\brm\b", _I)
# `--no-preserve-root` or any prefix of it from `--n` (rm has no other option that
# starts with n); the lookahead keeps `--n-x` and `--nope` out.
_NPR = "no-preserve-root"
_NO_PRESERVE = re.compile(
    r"--(?:" + "|".join(_NPR[:i] for i in range(len(_NPR), 0, -1)) + r")(?![\w-])", _I)
_DD_WORD = re.compile(r"\bdd\b", _I)
_KIT_WORD = re.compile(r"(?:hook-integrity-kit|hook_integrity_kit)\b", _I)
_BLESS = re.compile(r"\bbless\b", _I)


#: Block devices a write can destroy. A positive list on purpose: /dev/null, /dev/tty,
#: /dev/shm/x, /dev/urandom, /dev/stdin, /dev/pts/N and the like are not disks.
_BLOCK_DEV_RX = (r"/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|mapper/"
                 r"|md\d|loop\d|dm-\d)")
_BLOCK_DEV = re.compile(r"^" + _BLOCK_DEV_RX, _I)
_DD_TO_DEVICE = re.compile(r"\bof=[\"']?" + _BLOCK_DEV_RX, _I)
_RAW_DISK = re.compile(_BLOCK_DEV_RX, _I)
#: verbs whose every operand is written to or formatted
_DISK_ANY_OPERAND = ("tee", "shred", "wipefs", "blkdiscard", "sfdisk", "sgdisk", "mkswap")
#: verbs whose LAST operand (or -t DIR) is the destination; the others are sources
_DISK_DEST_VERBS = ("cp", "mv", "install")


_PATH_RUN = re.compile(r"(?<![\w.\-+/])/[\w.\-+/]*")


def _norm_dev_paths(text: str) -> str:
    """``text`` with every absolute path that resolves into /dev written as the plain
    /dev/... it names: ``//dev/sda``, ``///dev/sda``, ``/./dev/sda``, ``/tmp/../dev/sda``
    and ``/dev/../dev/sda`` are all /dev/sda. A path that does not end in /dev is left
    as written (``/tmp/dev/sda`` is not a disk)."""
    def fix(m: "re.Match[str]") -> str:
        norm = posixpath.normpath("/" + m.group(0).lstrip("/"))
        return norm if norm.startswith("/dev/") else m.group(0)
    return _PATH_RUN.sub(fix, text)


def _is_block_device(word: str) -> bool:
    return bool(_BLOCK_DEV.match(_norm_dev_paths(_DEV_DOTS.sub("/dev/", word))))


def _disk_write_to_device(command: str, ctx: Context) -> bool:
    """A write verb aimed at a block device: any operand of ``tee`` / ``shred`` /
    ``wipefs`` ..., the destination of ``cp`` / ``mv`` / ``install`` (the last operand,
    or the ``-t`` / ``--target-directory`` value). Reading a device (``cp /dev/sda
    img``) and a path that merely contains ``/dev/sd`` (``/tmp/dev/sda``) are not."""
    for verb in _DISK_ANY_OPERAND + _DISK_DEST_VERBS:
        for args in invocations(command, verb, quoted=True) + invocations(command, verb):
            flags, operands = _split_flags(args)
            if verb in _DISK_ANY_OPERAND:
                if any(_is_block_device(o) for o in operands):
                    return True
                continue
            target = None
            for k, a in enumerate(args):
                if a == "-t" or a == "--target-directory":
                    target = args[k + 1] if k + 1 < len(args) else None
                elif a.startswith("--target-directory="):
                    target = a.split("=", 1)[1]
                elif a.startswith("-t") and not a.startswith("--") and len(a) > 2:
                    target = a[2:]
            dest = target if target is not None else (operands[-1] if len(operands) >= 2 else None)
            if dest is not None and _is_block_device(dest):
                return True
    return False


def _rm_no_preserve_root(command: str, ctx: Context) -> bool:
    return _then_in_segment(command, _ends_of(_RM_WORD, command), _NO_PRESERVE)


_DEV_DOTS = re.compile(r"/dev(?:/\.?)+/")


def _disk_dd_to_device(command: str, ctx: Context) -> bool:
    # `/dev/./null` and `/dev//null` are /dev/null
    command = _norm_dev_paths(_DEV_DOTS.sub("/dev/", command))
    return _then_in_segment(command, _ends_of(_DD_WORD, command), _DD_TO_DEVICE)


_REDIRECT_DEV = re.compile(r">[|&]?\s*[\"']?" + _BLOCK_DEV_RX, _I)


def _redirect_to_device(command: str, ctx: Context) -> bool:
    return bool(_REDIRECT_DEV.search(_norm_dev_paths(command)))


def _kit_self_bless(command: str, ctx: Context) -> bool:
    return _then_in_segment(command, _ends_of(_KIT_WORD, command), _BLESS)


# The baseline file as a write target. Most verbs are one alternation. `sed` and
# `perl` edit in place only through an option, and the option may be anywhere in a
# cluster (`sed -Ei`, `perl -pi`) or after the script (`sed s/a/b/ -i f`,
# `perl -e 1 -i f`), so each is read option by option (_sed_in_place,
# _perl_in_place) over the words of its own segment.
_GT = re.compile(r">(?!&[0-9-])")      # `>&2`, `>&-` duplicate a descriptor: no file is written
_WRITE_VERB = re.compile(
    r"\b(?:tee|cp|mv|ln|install|rsync|truncate|rm|dd|unlink"
    r"|git\s+(?:checkout|restore))\b", _I)
# `git diff --output=FILE` (any abbreviation from `--ou`) writes its patch to FILE.
_OUTPUT_OPT = re.compile(r"--ou[a-z]*", _I)
_SED_HEAD = re.compile(r"\bg?sed\s+", _I)
_PERL_HEAD = re.compile(r"\bperl[\d.]*\s+", _I)
_BASELINE = re.compile(r"hook-integrity(?:-kit)?\.json", _I)
_SED_VALUE_LONG = ("expression", "file", "line-length")
_SED_VALUE_SHORT = "efl"
_PERL_ATTACHED = "CdDFmMx"     # the rest of the cluster is the value
_PERL_VALUE = "I"                # the rest of the cluster, or the next word
_PERL_INFO = "vVh"               # prints something and exits


def _sed_in_place(words: Sequence[str]) -> int:
    """Do the arguments of one ``sed`` ask for in-place editing? ``-i[SUFFIX]``
    anywhere in a short-option cluster (``-Ei``, ``-ni``, ``-i.bak``), before any
    letter that takes a value (``-e SCRIPT``, ``-f FILE``, ``-l N``); ``--in-place``
    or an abbreviation of it (``--i``, ``--in-pl``), with or without ``=SUFFIX``.
    GNU sed reads options in any position, so they are read to ``--``. Returns the
    index of the word that asks, or -1."""
    skip = False
    for k, w in enumerate(words):
        if skip:
            skip = False
            continue
        if w == "--":
            return -1
        if not w.startswith("-") or w == "-":
            continue
        if w.startswith("--"):
            nm, eq, _ = w.partition("=")
            nm = nm[2:]
            if nm and "in-place".startswith(nm.lower()):
                return k
            if nm and not eq and any(o.startswith(nm) for o in _SED_VALUE_LONG):
                skip = True
            continue
        letters = w[1:]
        for i, ch in enumerate(letters):
            if ch in "iI":
                return k
            if ch in _SED_VALUE_SHORT:
                skip = i + 1 == len(letters)
                break
    return -1


def _perl_in_place(words: Sequence[str]) -> int:
    """Do the switches of one ``perl`` ask for in-place editing: ``-i[EXT]`` anywhere
    in a cluster (``-pi``, ``-lpi``, ``-0pi``, ``-i.bak``) among the switches, which
    run to the first word that is not one (the script name, or the arguments after
    ``-e``) or to ``--``. Returns the index of the word that asks, or -1."""
    skip = False
    for k, w in enumerate(words):
        if skip:
            skip = False
            continue
        if w == "--" or not w.startswith("-") or w == "-":
            return -1
        letters = w[1:]
        i, n = 0, len(letters)
        while i < n:
            ch = letters[i]
            i += 1
            if ch == "i":
                return k
            if ch in _PERL_INFO:
                return -1
            if ch in "eE":
                skip = i == n
                break
            if ch in _PERL_VALUE:
                skip = i == n
                break
            if ch in _PERL_ATTACHED:
                break
            if ch in "0l":
                while i < n and letters[i].isdigit():
                    i += 1
    return -1


_BLANKS = re.compile(r"[ \t\r\f\v]*")


def _command_words(command: str, pos: int) -> Tuple[List[Tuple[int, int, str]], int]:
    """The words of the command that continues at ``pos``, as ``(start, end,
    unquoted)``, and where it ends: at a ``;``, ``|``, ``&``, newline, ``)`` or
    backtick that is not part of a redirect operator, with quotes respected (a ``;``
    inside ``'s/a/b/;s/c/d/'`` does not end it)."""
    out: List[Tuple[int, int, str]] = []
    n = len(command)
    while True:
        pos = _BLANKS.match(command, pos).end()
        if pos >= n:
            return out, n
        m = _WORD.match(command, pos)
        if m:
            out.append((m.start(), m.end(), _dequote(m.group(0))))
            pos = m.end()
            continue
        c = command[pos]
        if c in "<>":                                  # `>`, `>>`, `>|`, `>&`, `<&`, `<>`
            pos += 2 if command[pos + 1:pos + 2] in ("|", "&") else 1
        elif c == "&" and command.startswith("&>", pos):    # `&>`, `&>>`
            pos += 2
        elif c == "(":
            pos += 1
        else:
            return out, pos


def _in_place_names_baseline(command: str) -> bool:
    """Does a ``sed``/``perl`` that asks for in-place editing name the baseline
    anywhere in its own command (quotes respected)? The option word itself does not
    count: in ``sed -ihook-integrity.json`` the name is only a backup suffix."""
    for head_re, in_place in ((_SED_HEAD, _sed_in_place), (_PERL_HEAD, _perl_in_place)):
        pos = 0
        while True:
            head = head_re.search(command, pos)
            if not head:
                break
            words, stop = _command_words(command, head.end())
            k = in_place([w[2] for w in words])
            if k >= 0:
                lo, hi = words[k][0], words[k][1]
                for m in _BASELINE.finditer(command, head.end(), stop):
                    if not lo <= m.start() < hi:
                        return True
            pos = max(stop, head.end())          # a command is read once: linear
    return False


def _git_writes_baseline(command: str) -> bool:
    """``git archive -o FILE`` / ``--output FILE`` and ``git bundle create FILE`` with the
    baseline or config as FILE. Naming the baseline as an INPUT (``git archive HEAD
    -- .claude/hook-integrity.json``) reads it and is not a write."""
    for args in git_invocations(command):
        rest = _git_sub_args(args, "archive")
        if rest is not None:
            for k, a in enumerate(rest):
                if a == "--":
                    break
                name = a.split("=", 1)[0]
                long_output = len(name) > 2 and name.startswith("--o") and "--output".startswith(name)
                if (a == "-o" or (long_output and "=" not in a)) and k + 1 < len(rest) \
                        and _BASELINE.search(rest[k + 1]):
                    return True
                if long_output and "=" in a and _BASELINE.search(a):
                    return True
                if (a.startswith("-o") and not a.startswith("--") and len(a) > 2
                        and _BASELINE.search(a)):
                    return True
        rest = _git_sub_args(args, "bundle")
        if rest and rest[0] == "create":
            names = [w for w in rest[1:] if not w.startswith("-")]
            if names and _BASELINE.search(names[0]):
                return True
    return False


def _kit_baseline_shell_write(command: str, ctx: Context) -> bool:
    ends = _ends_of(_GT, command) + _ends_of(_WRITE_VERB, command) + _ends_of(_OUTPUT_OPT, command)
    return (_then_in_segment(command, ends, _BASELINE) or _in_place_names_baseline(command)
            or _git_writes_baseline(command))


_SETTINGS_FILE = re.compile(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", _I)


def _settings_link(command: str, ctx: Context) -> bool:
    """``ln`` (hard OR symbolic), ``link`` and ``cp -l`` / ``--link`` with a Claude Code
    settings file as an operand. A hard link is the same file under another name, so a
    later write to the innocent name is a write to the settings file; the Write guard
    also compares inodes, but a link that is never made cannot be abused."""
    for verb in ("ln", "link", "cp"):
        for args in invocations(command, verb, quoted=True) + invocations(command, verb):
            flags, operands = _split_flags(args)
            if verb == "cp" and not (_has_short(flags, "l") or any(
                    f.startswith("--l") and "link".startswith(f[2:].partition("=")[0])
                    for f in flags)):
                continue
            if any(_SETTINGS_FILE.search(_DEV_DOTS.sub("/dev/", o)) for o in operands):
                return True
    return False


# DELETE with no WHERE inside the SAME statement. A WHERE somewhere else on the line
# (`... | grep -i where`, `-U where`, a second `-c "SELECT 1 WHERE 1"`, `&& echo where`)
# does not guard it. The statement ends at the first of:
#   * a `;`;
#   * the end of the quoted string it sits in (`psql -c "DELETE FROM t"`), found by
#     pairing quotes the way the shell does, a backslash-escaped one (`\"`) as a level
#     of its own, so `bash -c "psql -c \"DELETE FROM t\" | cat"` ends at the inner quote;
#   * when it sits in no quoted string, or in one that never closes (an apostrophe
#     earlier on the line unbalances the pairing), the first shell separator, quote
#     character or newline. That reading is strict on purpose.
# A tool declared SQL (`commands.sql_tools`), or a heredoc before the statement, keeps
# its newlines and quotes inside the statement: only `;` ends it there.
_DELETE_FROM = re.compile(r"(?=(\bDELETE\s+FROM\s+[\w.\\\"`\[\]]+))", _I)
_WHERE = re.compile(r"\bWHERE\b", _I)
_QUOTE_EV = re.compile(r"(?<!\\)(\\*)([\"'])")
_STMT_BREAK = re.compile(r"[;\n|&)`\"']")


_LINE_COMMENT = re.compile(r"--(?=[ \t\r\n]|$)[^\n]*")


def strip_sql_comments(text: str) -> str:
    """``text`` with SQL comments replaced by a blank: ``/* ... */`` (an unclosed one
    is left alone) and ``-- ...`` to the end of the line (the ``--`` must be followed
    by a blank, as in MySQL, so a shell option such as ``--force`` is not one).
    Linear: a ``/*`` with no ``*/`` after it means no later one has either."""
    out: List[str] = []
    i = 0
    while True:
        a = text.find("/*", i)
        if a < 0:
            break
        b = text.find("*/", a + 2)
        if b < 0:
            break
        out.append(text[i:a])
        out.append(" ")
        i = b + 2
    out.append(text[i:])
    return _LINE_COMMENT.sub(" ", "".join(out))


def _sql_views(command: str) -> List[str]:
    """The text a SQL rule reads: as written, and with its comments removed. A rule
    that hits either hits: removing comments exposes a split keyword (a block comment
    between DELETE and FROM) and drops a WHERE that was only inside a comment, while
    the written text keeps a statement that a stray ``-- `` in the shell part of the
    line would otherwise swallow."""
    plain = strip_sql_comments(command)
    return [command] if plain == command else [command, plain]


def _sql_rx(pattern: str) -> Callable[[str, "Context"], bool]:
    rx = re.compile(pattern, _I)

    def hit(command: str, ctx: Context) -> bool:
        return any(rx.search(v) for v in _sql_views(command))
    return hit


def _enclosing_frame_ends(view: str, positions: List[int]) -> List[Optional[int]]:
    """For each position (ascending), the index of the quote that closes the quoted
    string holding it, or None when it is in none, or in one that never closes. A
    quote character closes the innermost open string when it is the same character
    with the same number of backslashes in front; otherwise it opens a nested one.
    One pass over the quote characters: linear."""
    ends: List[Optional[int]] = []                # per frame: closing index, if any
    stack: List[Tuple[str, int, int]] = []        # (character, backslashes, frame id)
    inside: List[int] = []                        # per position: frame id, or -1
    events = list(_QUOTE_EV.finditer(view))
    ei = 0

    def feed(upto: int) -> None:
        nonlocal ei
        while ei < len(events) and events[ei].start() < upto:
            m = events[ei]
            ei += 1
            ch, bs = m.group(2), len(m.group(1))
            if stack and stack[-1][0] == ch and stack[-1][1] == bs:
                ends[stack.pop()[2]] = m.end() - 1
            else:
                ends.append(None)
                stack.append((ch, bs, len(ends) - 1))

    for pos in positions:
        feed(pos)
        inside.append(stack[-1][2] if stack else -1)
    feed(len(view) + 1)
    return [ends[f] if f >= 0 else None for f in inside]


def _unguarded_delete(view: str, ctx: Context) -> bool:
    matches = list(_DELETE_FROM.finditer(view))
    if not matches:
        return False
    where = [m.start() for m in _WHERE.finditer(view)]
    semis = [i for i, ch in enumerate(view) if ch == ";"]
    strict = [m.start() for m in _STMT_BREAK.finditer(view)]
    heredoc = view.find("<<")
    closes = _enclosing_frame_ends(view, [m.start(1) for m in matches])
    for m, close in zip(matches, closes):
        start = m.end(1)
        if close is not None:
            pool, limit = semis, close
        elif ctx.sql_input or 0 <= heredoc < m.start(1):
            pool, limit = semis, len(view)
        else:
            pool, limit = strict, len(view)
        i = bisect.bisect_left(pool, start)
        bound = min(limit, pool[i]) if i < len(pool) else limit
        j = bisect.bisect_left(where, start)
        if not (j < len(where) and where[j] < bound):
            return True
    return False


def _sql_delete_without_where(command: str, ctx: Context) -> bool:
    return any(_unguarded_delete(view, ctx) for view in _sql_views(command))


# TRUNCATE. `TRUNCATE TABLE` is SQL wherever it appears. A bare `TRUNCATE name` is
# also coreutils' `truncate file -s 0`, so it counts only with SQL around it: a SQL
# client on the line, a tool declared SQL, or a statement that ends where SQL's does
# (`;`, a closing quote, the end of the text, after a name list).
_TRUNC_TABLE = re.compile(r"\bTRUNCATE\s+TABLE\b", _I)
_TRUNC_BARE = re.compile(r"\bTRUNCATE\s+(?!TABLE\b)[A-Za-z_\"`\[]", _I)
_TRUNC_STATEMENT = re.compile(
    r"\bTRUNCATE\s+(?!TABLE\b)(?:ONLY\s+)?[\w.\"`\[\]$]+(?:\s*,\s*[\w.\"`\[\]$]+)*"
    r"\s*(?:[;\"'`)]|$)", _I | re.M)
_SQL_CLIENT = re.compile(
    r"\b(?:psql|pgcli|mysql|mycli|mariadb|sqlite3?|sqlcmd|sqlplus|usql|duckdb|isql"
    r"|clickhouse-client|cockroach|mongosh?)\b", _I)


def _sql_truncate(command: str, ctx: Context) -> bool:
    for v in _sql_views(command):
        if _TRUNC_TABLE.search(v):
            return True
        if ctx.sql_input or _SQL_CLIENT.search(v):
            if _TRUNC_BARE.search(v):
                return True
        elif _TRUNC_STATEMENT.search(v):
            return True
    return False


_KILL_NAMES = frozenset(("9", "kill", "sigkill"))


def _signal_is_kill(value: str) -> bool:
    v = value.lower().lstrip("-")
    if v.isdigit():
        v = v.lstrip("0") or "0"
    return v in _KILL_NAMES


def _kill_everything(command: str, ctx: Context) -> bool:
    """``kill`` with the KILL signal (``-9``, ``-KILL``, ``-SIGKILL``, ``-s 9``,
    ``-s9``, ``-sKILL``, ``-n 9``, ``-n9``, ``--signal KILL`` or ``--signal=9``, a
    zero-padded number included) aimed at pid ``-1`` (or ``-01``...), which is every
    process the caller may signal, with or without ``--`` in front of it."""
    for args in invocations(command, "kill"):
        killing, everything, skip = False, False, False
        for i, a in enumerate(args):
            if skip:
                skip = False
                continue
            low = a.lower()
            if re.fullmatch(r"-0*1", a):
                everything = True
            elif low in ("-s", "-n", "--signal"):
                if i + 1 < len(args) and _signal_is_kill(args[i + 1]):
                    killing = True
                skip = True
            elif low.startswith("--signal="):
                killing = killing or _signal_is_kill(low[9:])
            elif low.startswith("-") and not low.startswith("--") and _signal_is_kill(low[1:]):
                killing = True
            elif low[:2] in ("-s", "-n") and len(low) > 2 and not low.startswith("--"):
                killing = killing or _signal_is_kill(low[2:])
        if killing and everything:
            return True
    return False


_FORK_OPEN = re.compile(r":\(\)\s*\{")


def _fork_bomb(command: str, ctx: Context) -> bool:
    """``:(){`` then, on the same line, a ``|`` and later a ``}``."""
    done_to = -1
    for m in _FORK_OPEN.finditer(command):
        e = m.end()
        if e <= done_to:                       # this line was already judged
            continue
        nl = command.find("\n", e)
        nl = len(command) if nl < 0 else nl
        done_to = nl
        pipe = command.find("|", e, nl)
        if pipe >= 0 and command.find("}", pipe + 1, nl) >= 0:
            return True
    return False


# pipe-to-shell. `curl ... | <reader>`: after each pipe that follows the first
# curl/wget of a segment, the command that runs is found (transparent wrappers such
# as sudo, env, nice, timeout are skipped, their options included) and judged: does
# it read a program from stdin? `||` is an or-list, not a pipe; `|&` is a pipe. A
# segment ends at `;`, `&&`, a lone `&` or a newline, but NOT at the `&` of `2>&1`,
# `&>` or `|&`, and not at a newline whose next line starts with `|`. A
# backslash-newline is joined before any rule is judged (check_command).
#
# Reading is word by word with a fixed budget of _READER_STEPS words per pipe. A
# reader that is still skipping wrappers, options or assignments when the budget
# runs out cannot be judged, and the command is REFUSED (WorkBudgetExceeded), as for
# the pipe cap: a hook that fails open is a way past the rule.
_DOWNLOADER = re.compile(r"\b(?:curl|wget)\b", _I)
_SEG_PIPE = re.compile(r"(?:[^;&\n]|(?<=[>|])&|&(?=>)|\n(?=[ \t]*\|))+")
# Blanks and comments, then one shell word: runs of plain characters, '...',
# "..." and backslash escapes. A quote that never closes is a plain character.
_SKIP = re.compile(r"(?:[ \t\r\n\f\v]|#[^\n]*)*")
_WORD = re.compile(r"(?:'[^']*'|\"(?:[^\"\\]|\\.)*\"|\\.|[^\s|;&<>()'\"\\`]|['\"\\])+",
                   re.S)
_UNQUOTE = re.compile(r"'([^']*)'|\"((?:[^\"\\]|\\.)*)\"|\\(.)", re.S)
_DQ_ESCAPE = re.compile(r"\\([\"\\$`])")
_ASSIGN = re.compile(r"[A-Za-z_]\w*=")
_SHELL_NAME = re.compile(r"(?:r?(?:ba|z|k)|da|fi|a|c|tc)?sh[\d.]*", _I)
_SHELL_VAR = re.compile(r"\$\{?SHELL\}?")
_PYTHON_NAME = re.compile(r"python[\d.]*", _I)
_READER_STEPS = 32           # words read after one pipe
_NEST_DEPTH = 4              # `su -c '...'` / `env -S '...'` strings read inside strings


class _Spec(NamedTuple):
    short_arg: str = ""            # option letters that take a value
    long_arg: frozenset = frozenset()
    not_run: str = ""              # letters meaning "this is not a run" (`command -v`)
    not_run_long: frozenset = frozenset()
    shell: str = ""                # letters meaning "start a shell" (`sudo -s`)
    shell_long: frozenset = frozenset()
    positionals: int = 0           # words before the command (`timeout 5 cmd`)
    bare_shell: bool = False       # with no command it starts a shell (`pkexec`)


def _w(short_arg="", long_arg=(), not_run="", not_run_long=(), shell="", shell_long=(),
       positionals=0, bare_shell=False):
    return _Spec(short_arg, frozenset(long_arg), not_run, frozenset(not_run_long), shell,
                 frozenset(shell_long), positionals, bare_shell)


# Transparent wrappers: they run the command that follows them.
_WRAPPERS = {
    "sudo": _w("ughpCUDRTrt",
               ("--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type",
                "--close-from", "--chroot", "--command-timeout", "--other-user"),
               not_run="lveV", not_run_long=("--list", "--validate", "--edit", "--version",
                                             "--help"),
               shell="si", shell_long=("--shell", "--login")),
    "doas": _w("uC", shell="s"),
    "pkexec": _w(long_arg=("--user",), bare_shell=True),
    "env": _w("uCaS", ("--unset", "--chdir", "--argv0")),
    "nice": _w("n", ("--adjustment",)),
    "ionice": _w("cn", ("--class", "--classdata")),
    "command": _w(not_run="vV"),
    "timeout": _w("ks", ("--kill-after", "--signal"), positionals=1),
    "stdbuf": _w("ioe", ("--input", "--output", "--error")),
    "time": _w("fo", ("--format", "--output")),
    "exec": _w("a"),
    "nohup": _w(), "setsid": _w(), "builtin": _w(),
    "busybox": _w(), "toybox": _w(), "unbuffer": _w(),
}
_SU_LONG_ARG = frozenset(("--group", "--supp-group", "--shell", "--whitelist-environment"))


class _Interp(NamedTuple):
    program: str = ""              # letters after which the program is NOT on stdin
    value: str = ""                # letters that take a value (attached or the next word)
    attached: str = ""             # letters that swallow the rest of the cluster
    digits: str = ""               # letters that swallow only the digits after them
    long_prog: frozenset = frozenset()
    long_value: frozenset = frozenset()


_INTERPRETERS = {
    "python": _Interp(program="cmVh", value="WXQ", long_prog=frozenset(("--version", "--help")),
                      long_value=frozenset(("--check-hash-based-pycs",))),
    "perl": _Interp(program="eEvVh", value="I", attached="MmxCidDFt", digits="0l"),
    "ruby": _Interp(program="eh", value="rICEFX", attached="WxiKT", digits="0",
                    long_prog=frozenset(("--version", "--help", "--copyright"))),
    "node": _Interp(program="epcvh", value="rC",
                    long_prog=frozenset(("--eval", "--print", "--check", "--version",
                                         "--help", "--v8-options")),
                    long_value=frozenset(("--require", "--import", "--loader",
                                          "--experimental-loader", "--conditions",
                                          "--input-type"))),
    "php": _Interp(program="rfRBFEvhimlswS", value="dczt"),
}


def _dequote(w: str) -> str:
    """Remove matched quotes and backslash escapes; a quote that never closes stays."""
    if "'" not in w and '"' not in w and "\\" not in w:
        return w

    def one(m):
        if m.group(1) is not None:
            return m.group(1)
        if m.group(2) is not None:
            return _DQ_ESCAPE.sub(r"\1", m.group(2))
        return m.group(3)
    return _UNQUOTE.sub(one, w)


class _Reader:
    """Shell words from ``text`` starting at ``pos``, at most _READER_STEPS of them."""
    __slots__ = ("text", "pos", "steps")

    def __init__(self, text: str, pos: int = 0):
        self.text, self.pos, self.steps = text, pos, 0

    def word(self) -> Optional[str]:
        """The next word (unquoted), or None at the end of the command: a ``|``, ``;``,
        ``&``, redirect, ``(`` or the end of the text. Comments are skipped."""
        self.steps += 1
        if self.steps > _READER_STEPS:
            raise WorkBudgetExceeded(
                f"more than {_READER_STEPS} words to read after a pipe to find the command")
        pos = _SKIP.match(self.text, self.pos).end()
        m = _WORD.match(self.text, pos)
        if not m:
            self.pos = pos
            return None
        self.pos = m.end()
        return _dequote(m.group(0))

    def mark(self):
        return self.pos, self.steps

    def reset(self, mark):
        self.pos, self.steps = mark


def _judge_text(text: str, depth: int) -> bool:
    """Judge a command held in a string (``su -c '...'``, ``env -S '...'``)."""
    if depth >= _NEST_DEPTH:
        raise WorkBudgetExceeded(f"command strings nested more than {_NEST_DEPTH} deep")
    return _judge(_Reader(text), depth + 1)


def _options(r: _Reader, name: str, spec: _Spec, depth: int):
    """Skip a wrapper's own options. Returns ``(verdict, shell)``: ``verdict`` is
    True/False when the answer is already known, None to go on and read the command;
    ``shell`` is True when the wrapper was asked to start a shell."""
    shell = spec.bare_shell
    is_env = name == "env"
    while True:
        mark = r.mark()
        w = r.word()
        if w is None or w == "--":
            return None, shell
        if w == "-" and is_env:                  # env - == env -i
            continue
        if w[0] != "-" or w == "-":
            r.reset(mark)                        # the command starts here
            return None, shell
        if w.startswith("--"):
            nm, eq, val = w.partition("=")
            if nm in spec.not_run_long:
                return False, shell
            if nm in spec.shell_long:
                shell = True
            if is_env and nm == "--split-string":
                v = val if eq else r.word()
                if v is not None and _judge_text(v, depth):
                    return True, shell
            elif nm in spec.long_arg and not eq:
                r.word()
            continue
        letters = w[1:]                          # a cluster: -Eu, -iC, -n5
        for i, ch in enumerate(letters):
            if ch in spec.not_run:
                return False, shell
            if ch in spec.shell:
                shell = True
            if ch in spec.short_arg:
                rest = letters[i + 1:]
                if is_env and ch == "S":         # env -S 'cmd args': a command string
                    v = rest or r.word()
                    if v is not None and _judge_text(v, depth):
                        return True, shell
                elif not rest:
                    r.word()
                break


_RUNUSER_SHORT_ARG = "ugGscw"        # runuser -l and -m/-p/-P/-f take no value
_RUNUSER_LONG_ARG = _SU_LONG_ARG | {"--user", "--command", "--session-command"}


def _run_rest(r: _Reader, depth: int) -> bool:
    """Judge the command that follows ``runuser -u USER``: skip the options that may
    still follow (``-g GROUP``, ``-G GROUP``, ``-s SHELL``, clustered or long) and an
    optional ``--``."""
    while True:
        mark = r.mark()
        w = r.word()
        if w is None:
            return False
        if w == "--":
            break
        if w[0] != "-" or w == "-":
            r.reset(mark)
            break
        if w.startswith("--"):
            nm, eq, _ = w.partition("=")
            if nm in _RUNUSER_LONG_ARG and not eq:
                r.word()
            continue
        for i, ch in enumerate(w[1:], 2):
            if ch in _RUNUSER_SHORT_ARG:
                if i == len(w):
                    r.word()
                break
    return _judge(r, depth)


def _su(r: _Reader, name: str, depth: int) -> bool:
    """``su`` / ``runuser``: with no ``-c`` they start the user's shell, which reads
    stdin; with ``-c STRING`` the string is judged. ``runuser -u USER COMMAND`` runs
    COMMAND directly."""
    cmd = None
    while True:
        w = r.word()
        if w is None:
            break
        if w[0] != "-" or w in ("-", "--"):
            continue                              # the user name, or a login dash
        if w.startswith("--"):
            nm, eq, val = w.partition("=")
            if nm in ("--command", "--session-command"):
                cmd = val if eq else r.word()
            elif nm == "--user" and name == "runuser":
                if not eq:
                    r.word()
                return _run_rest(r, depth)
            elif nm in _SU_LONG_ARG and not eq:
                r.word()
            continue
        letters = w[1:]
        for i, ch in enumerate(letters):
            rest = letters[i + 1:]
            if ch == "c":
                cmd = rest or r.word()
                break
            if ch == "u" and name == "runuser":
                if not rest:
                    r.word()
                return _run_rest(r, depth)
            if ch in "gGsw":
                if not rest:
                    r.word()
                break
    if cmd is None:
        return True
    return _judge_text(cmd, depth)


def _reads_program(r: _Reader, spec: _Interp) -> bool:
    """Does an interpreter run with these arguments read its program from stdin?
    Not if an option names the program (``-m``, ``-c``, ``-e``, ``-p``), prints a
    version, or the first non-option word is a script path."""
    while True:
        w = r.word()
        if w is None or w == "-":
            return True
        if w == "--":
            w = r.word()
            return w is None or w == "-"
        if w[0] != "-":
            return False
        if w.startswith("--"):
            nm, eq, _ = w.partition("=")
            if nm in spec.long_prog:
                return False
            if nm in spec.long_value and not eq:
                r.word()
            continue
        i, n = 1, len(w)
        while i < n:
            ch = w[i]
            i += 1
            if ch in spec.program:
                return False
            if ch in spec.value:
                if i >= n:
                    r.word()
                break
            if ch in spec.attached:
                break
            if ch in spec.digits:
                while i < n and w[i].isdigit():
                    i += 1


def _judge(r: _Reader, depth: int = 0) -> bool:
    """Is the command that starts at the reader's position a shell or interpreter
    that reads a program from stdin, possibly behind transparent wrappers?"""
    pending = False          # a shell was asked for (`sudo -s`) and no command follows
    while True:
        tok = r.word()
        if tok is None:
            return pending
        if _ASSIGN.match(tok):                    # `A=1 bash`
            continue
        pending = False
        name = tok.rsplit("/", 1)[-1]
        low = name.lower()
        if _SHELL_VAR.fullmatch(tok) or _SHELL_NAME.fullmatch(name):
            return True
        spec = _WRAPPERS.get(low)
        if spec is not None:
            verdict, shell = _options(r, low, spec, depth)
            if verdict is not None:
                return verdict
            for _ in range(spec.positionals):
                r.word()
            pending = shell
            continue
        if low in ("su", "runuser"):
            return _su(r, low, depth)
        interp = _INTERPRETERS.get("python" if _PYTHON_NAME.fullmatch(low) else low)
        return interp is not None and _reads_program(r, interp)


def _reader_at(command: str, pos: int) -> bool:
    """Is the command that starts after a pipe (at ``pos``) a shell or interpreter
    reading stdin, possibly behind transparent wrappers?"""
    if command.startswith("&", pos):            # `|&`
        pos += 1
    return _judge(_Reader(command, pos))


def _piped_to_reader(command: str) -> bool:
    for sm in _SEG_PIPE.finditer(command):
        a, b = sm.span()
        c = _DOWNLOADER.search(command, a, b)
        if not c:
            continue
        pos, seen = c.end(), 0
        while True:
            p = command.find("|", pos, b)
            if p < 0:
                break
            if command.startswith("||", p):     # an or-list is not a pipe
                pos = p + 2
                continue
            if p > a and command[p - 1] == ">":  # `>|` is a redirect, not a pipe
                pos = p + 1
                continue
            seen += 1
            if seen > MAX_PIPES:
                raise WorkBudgetExceeded(
                    f"more than {MAX_PIPES} pipes after one curl/wget")
            if _reader_at(command, p + 1):
                return True
            pos = p + 1
    return False


# A shell or interpreter name, then a blank, or `<` directly (`bash<(curl x)`).
_SHELL_HEAD = re.compile(
    r"\b(?:(?:r?(?:ba|z|k)|da|fi|a|c|tc)?sh[\d.]*|python[\d.]*|perl[\d.]*|ruby[\d.]*|node"
    r"|php[\d.]*)(?:\s+|(?=<))", _I)
_OPTION_WORD = re.compile(r"([-+]\S*)\s+")
_NONWS_RE = re.compile(r"\S*")
_BLANKS_NL = re.compile(r"\s*")
#: Options of a shell that take the next word as their VALUE: `-o NAME`, `-O NAME`
#: (alone or last in a cluster, `-eo pipefail`), `--rcfile FILE`, `--init-file FILE`.
_SHELL_LONG_VALUE = frozenset(("--rcfile", "--init-file"))
# What the shell or interpreter is handed: a process substitution (`<(curl x)`, also
# as an input redirect, `< <(curl x)`) or a here-string (`<<< "$(curl x)"`).
_PROC_SUBST = re.compile(
    r"(?:<[ \t]*)?<\(\s*(?:curl|wget)\b|<<<[ \t]*[\"']?(?:\$\(|`)\s*(?:curl|wget)\b", _I)
# A shell, `su`, or an interpreter run with an inline-program option, handed a command
# substitution that downloads: `sh -c "$(curl x)"`, `su -c "$(curl x)"`, `python3 -c
# "$(curl x)"`, with text before the `$(` (`"x$(curl x)"`), a path (`/usr/bin/curl`) or
# a transparent wrapper (`command curl`, `sudo curl`, `env curl`) inside it.
_SHELL_ONLY_HEAD = re.compile(
    r"\b(?:(?:r?(?:ba|z|k)|da|fi|a|c|tc)?sh[\d.]*|su|runuser|python[\d.]*|perl[\d.]*|ruby[\d.]*"
    r"|node|php[\d.]*)\s+", _I)
_SUBST_DOWNLOAD = re.compile(
    r"[\"']?[^\s\"'`$]*(?:\$\(|`)\s*(?:(?:command|sudo|doas|env|nice|nohup|exec|time|builtin"
    r"|busybox|stdbuf|setsid|timeout)\s+(?:-\S+\s+|\d+\s+)*)*(?:[\w./-]*/)?(?:curl|wget)\b", _I)
_INLINE_LETTERS = {"perl": "eE", "ruby": "eE", "node": "eE", "php": "r"}
# `source <(curl ...)` and `. <(curl ...)`: the builtin reads and runs the download.
# It must start a command (line start, `;`, `&`, `|`, `(`, `{`, a quote), so that
# `echo . <(curl x)` is not read as a source.
_SOURCE_SUBST = re.compile(
    r"(?:^|[;&|(\n{`'\"])[ \t]*(?:source|\.)[ \t]+<\(\s*(?:curl|wget)\b", _I)


def _shell_options_end(command: str, p: int) -> int:
    """Where the options of a shell invocation end, starting after the shell name."""
    while True:
        m = _OPTION_WORD.match(command, p)
        if not m:
            return p
        p = m.end()
        opt = m.group(1)
        if opt == "--":
            return p
        takes_value = (opt in _SHELL_LONG_VALUE
                       or (not opt.startswith("--") and len(opt) > 1
                           and opt[-1] in "oO"))
        if takes_value:
            v = _NONWS_RE.match(command, p)
            p = _BLANKS_NL.match(command, v.end()).end()


def _shell_reads_download(command: str) -> bool:
    """``bash <(curl ...)``, ``bash < <(curl ...)`` and ``bash <<< "$(curl ...)"``
    (also for ``python``, ``perl``, ``ruby``, ``node``, ``php``), with options in front (``bash -o pipefail <(curl ...)``;
    the value of ``-o``/``-O``/``--rcfile``/``--init-file`` is skipped). A shell
    name is read together with the run of option words after it; a later ``sh``
    inside that run would read a suffix of it, so the scan resumes after the run."""
    pos = 0
    while True:
        head = _SHELL_HEAD.search(command, pos)
        if not head:
            return False
        flags_end = _shell_options_end(command, head.end())
        if _PROC_SUBST.match(command, flags_end):
            return True
        pos = max(head.end(), flags_end)


def _shell_c_runs_download(command: str) -> bool:
    """``sh -c "$(curl ...)"`` with the ``-c`` anywhere among the shell's options: in a
    cluster (``bash -lc``, ``-ec``), after other options (``-x -c``) or after an option
    value (``-o pipefail -c``). The options are read word by word, as for
    ``_shell_options_end``; the scan resumes after them, so it is linear."""
    pos = 0
    while True:
        head = _SHELL_ONLY_HEAD.search(command, pos)
        if not head:
            return False
        p, has_c = head.end(), False
        name = command[head.start():head.end()].strip().rsplit("/", 1)[-1].lower()
        letters = next((v for k, v in _INLINE_LETTERS.items() if name.startswith(k)), "c")
        while not has_c:
            m = _OPTION_WORD.match(command, p)
            if not m:
                break
            opt = m.group(1)
            p = m.end()
            if opt == "--":
                break
            if (not opt.startswith("--") and opt[0] == "-"
                    and any(ch in letters for ch in opt[1:])):
                has_c = True
            elif opt in _SHELL_LONG_VALUE or (not opt.startswith("--") and len(opt) > 1
                                              and opt[-1] in "oO"):
                v = _NONWS_RE.match(command, p)
                p = _BLANKS_NL.match(command, v.end()).end()
        if has_c and _SUBST_DOWNLOAD.match(command, p):
            return True
        pos = max(head.end(), p)


def _pipe_to_shell(command: str, ctx: Context) -> bool:
    return (_piped_to_reader(command) or _shell_reads_download(command)
            or _shell_c_runs_download(command)
            or _SOURCE_SUBST.search(command) is not None)


_PAGER_OPT = re.compile(
    r"""(?<![\w-])(?:-O|--open-files-in-pager(?:=|[ \t]+))[ \t]*"""
    r"""(?:'(?P<sq>[^']*)'|"(?P<dq>[^"]*)"|(?P<bare>[^\s;&|]+))""", _I)
_SEGMENT_BREAK = re.compile(r"[;&|\n]")


def _git_grep_pager(command: str, ctx: Context) -> bool:
    """``git grep -O CMD`` / ``--open-files-in-pager=CMD`` runs CMD with the matching
    files: CMD is judged like any command line (a pipe into a shell inside it, a
    forbidden write, ...). Linear: each option is looked at once, with the words that
    precede it in its own segment (at most 400 characters)."""
    for m in _PAGER_OPT.finditer(command):
        before = command[max(0, m.start() - 400):m.start()]
        cut = [x.end() for x in _SEGMENT_BREAK.finditer(before)]
        words = before[cut[-1]:].split() if cut else before.split()
        if "git" not in words or "grep" not in words:
            continue
        pager = m.group("sq") or m.group("dq") or m.group("bare") or ""
        if pager and pager != command and check_command(pager, None, ctx) is not None:
            return True
    return False


# ── the default rule set ─────────────────────────────────────────────────────
#
# Every rule here has a test that must fire and a benign neighbour that must not
# (tests/test_commands.py). Add a rule only with both.

DEFAULT_RULES: Tuple[Rule, ...] = (
    Rule("rm-recursive-root-or-home",
         "recursive delete of the filesystem root, a top-level directory, or a home directory",
         "CRITICAL", func=_rm_root_or_home),
    Rule("rm-no-preserve-root", "rm with --no-preserve-root", "CRITICAL",
         func=_rm_no_preserve_root),
    Rule("git-force-push-protected-branch", "force push to, or remote delete of, a protected branch", "HIGH",
         func=_git_force_push_protected),
    Rule("git-delete-protected-branch", "force-delete a protected branch", "CRITICAL",
         func=_git_delete_protected_branch),
    Rule("git-clean-force-directories", "git clean forcing removal of untracked directories", "HIGH",
         func=_git_clean_force_directories),
    Rule("pipe-to-shell", "downloaded content piped straight into a shell or interpreter", "HIGH",
         func=_pipe_to_shell),
    Rule("git-grep-pager-command",
         "git grep -O / --open-files-in-pager running a command that is itself blocked "
         "(for example a download piped into a shell)", "HIGH", func=_git_grep_pager),
    Rule("disk-format", "filesystem format (mkfs, mke2fs, mkdosfs, mkntfs ...)", "CRITICAL",
         pattern=r"\b(?:mkfs(?:\.\w+)?|mke[234]fs|mkdosfs|mkntfs|mkreiserfs|mkudffs)\b"),
    Rule("disk-dd-to-device", "dd writing to a block device", "CRITICAL",
         func=_disk_dd_to_device),
    Rule("disk-write-to-device",
         "tee, cp, mv, install, shred, wipefs, blkdiscard, sfdisk, sgdisk or mkswap writing "
         "a raw disk device",
         "CRITICAL", func=_disk_write_to_device),
    Rule("disk-redirect-to-device", "shell redirect onto a raw disk device", "CRITICAL",
         func=_redirect_to_device),
    Rule("chmod-777-recursive-or-root",
         "chmod 777 applied recursively, or to the root/home/top-level directory",
         "HIGH", func=_chmod_777),
    Rule("chown-recursive-root", "recursive chown of the root/home/top-level directory",
         "CRITICAL", func=_chown_recursive_root),
    Rule("fork-bomb", "fork bomb", "CRITICAL", func=_fork_bomb),
    Rule("kill-all-processes", "kill -9 -1 (every process you own), in any spelling of KILL",
         "CRITICAL", func=_kill_everything),
    # The baseline is what `verify` trusts. `check-write` refuses it through the
    # Write tool; without these two, the same agent could re-bless (or rewrite,
    # restore, link or delete the baseline) through Bash and leave no drift.
    Rule("kit-self-bless",
         "re-blessing the hook-integrity baseline (a person runs `bless` after review)",
         "HIGH", func=_kit_self_bless),
    Rule("kit-baseline-shell-write",
         "writing, restoring, linking or deleting the hook-integrity baseline or config",
         "HIGH", func=_kit_baseline_shell_write),
    Rule("kit-settings-link",
         "linking (ln, link, cp -l) a Claude Code settings file: the link is the same file "
         "under another name", "HIGH", func=_settings_link),
    Rule("sql-drop-database", "DROP DATABASE", "CRITICAL",
         func=_sql_rx(r"\bDROP\s+DATABASE\b")),
    Rule("sql-drop-schema", "DROP SCHEMA (with or without CASCADE)", "CRITICAL",
         func=_sql_rx(r"\bDROP\s+SCHEMA\b")),
    # The negative lookahead sits DIRECTLY after the word boundary. Behind a
    # greedy `.*` it would be unreachable (`.*` eats to end of string, where the
    # lookahead trivially succeeds) and the rule would block the guarded form its
    # own name permits. tests/test_commands.py ratchets that class for every rule.
    # Policy note: IF EXISTS does not make a drop safe, it only silences the error
    # when the table is absent. This rule's policy is the one its name states.
    Rule("sql-drop-table-unguarded", "DROP TABLE without IF EXISTS", "HIGH",
         func=_sql_rx(r"\bDROP\s+TABLE\b(?!\s+IF\s+EXISTS)")),
    # `truncate file -s 0` (coreutils) is not SQL: see _sql_truncate.
    Rule("sql-truncate-table", "SQL TRUNCATE", "HIGH", func=_sql_truncate),
    # No WHERE before the statement ends (`;`, a closing quote, or the end of
    # the input). The earlier pattern demanded a trailing `;`, so the same
    # statement without one, which every SQL client accepts, went through.
    Rule("sql-delete-without-where", "DELETE without a WHERE clause", "CRITICAL",
         func=_sql_delete_without_where),
)

#: Read-only commands whose own text may legitimately contain a dangerous-looking
#: string. They excuse a hit only under the conditions in check_command. Each verb is
#: a WHOLE word (followed by a blank or the end): with `\b`, `echo=1 <command>` (an
#: assignment, then the real command) read as an `echo`.
SAFE_PREFIXES: Tuple[str, ...] = (
    r"^git\s+status(?=\s|$)",
    r"^git\s+log(?=\s|$)",
    r"^git\s+diff(?=\s|$)",
    r"^ls(?=\s|$)",
    r"^cat(?=\s|$)",
    r"^echo(?=\s|$)",
)

_CHAIN = re.compile(r"[;|&\n]")
#: Options that make a "read-only" git command write a file or run a program:
#: `--output[=FILE]` (any abbreviation from `--ou`), `--ext-diff` and `--textconv`.
_WRITING_OPTS = re.compile(r"\s--(?:ou[a-z-]*|ext[a-z-]*|textconv)\b", _I)


def _ALLOWLIST_BLOCKS(text: str) -> bool:
    """Does a segment of an allowlisted command carry an option that writes a file
    or runs a configured program? Then the allowlist does not excuse it."""
    return _WRITING_OPTS.search(text) is not None
#: Constructs that run a command somewhere other than the front of the line, or
#: turn a read into a write. Their presence disqualifies the allowlist.
_ESCAPES = re.compile(r"\$\(|`|<\(|>")


def segments(command: str) -> List[str]:
    # Split on the separator alone and strip afterwards: a `\s*` in the separator
    # pattern is quadratic on a long run of blanks.
    return [t for t in (s.strip() for s in _CHAIN.split(command)) if t]


def active_rules(cfg: Optional[dict] = None) -> Tuple[List[Rule], Context, List[str]]:
    """Default rules minus disabled ids, plus the config's extra regex rules.
    Returns (rules, context, warnings)."""
    sec = cfgmod.section(cfg or {}, "commands")
    warnings: List[str] = []
    disabled = set(cfgmod.str_list(sec, "disable"))
    rules = [r for r in DEFAULT_RULES if r.id not in disabled]
    for i, raw in enumerate(sec.get("extra_rules") or []):
        if not isinstance(raw, dict) or not isinstance(raw.get("pattern"), str):
            warnings.append(f"commands.extra_rules[{i}] skipped: needs a 'pattern' string")
            continue
        try:
            re.compile(raw["pattern"])
        except re.error as e:
            warnings.append(f"commands.extra_rules[{i}] skipped: bad regex ({e})")
            continue
        rules.append(Rule(str(raw.get("id") or f"extra-{i}"),
                          str(raw.get("description") or raw["pattern"]),
                          str(raw.get("severity") or "HIGH"), pattern=raw["pattern"]))
    branches = tuple(cfgmod.str_list(sec, "protected_branches")) or ("main", "master")
    return rules, Context(protected_branches=branches), warnings


#: An odd run of backslashes before a newline: the last one and the newline vanish.
_JOIN = re.compile(r"(?<!\\)((?:\\\\)*)\\\n")


_KEEP_QUOTED = re.compile(r"[\s;&|<>()`]")


def _unquote_words(text: str) -> str:
    """``text`` with every shell word unquoted (matched quotes and backslash
    escapes removed) unless that would expose a blank or an operator that the quotes
    were hiding. Linear."""
    if "'" not in text and '"' not in text and "\\" not in text:
        return text
    out: List[str] = []
    last = 0
    for m in _WORD.finditer(text):
        out.append(text[last:m.start()])
        w = m.group(0)
        plain = _dequote(w)
        # A quoted string that holds blanks or operators stays as written: removing
        # its quotes would let a `|` or `;` inside it read as a real one.
        out.append(w if _KEEP_QUOTED.search(plain) else plain)
        last = m.end()
    out.append(text[last:])
    return "".join(out)


# ── quoted arguments of read-only and commit commands are data ───────────────
#
# `echo 'DROP TABLE users;'`, `grep -rn 'DELETE FROM x' src/` and
# `git commit -m "docs: curl x | sh"` name a dangerous command without running it.
# Rules read text, so they refuse these. Second chance, after the rules hit and the
# allowlist did not excuse it: if EVERY command on the line is one whose quoted
# arguments are data, those arguments are blanked and the rules run again on what is
# left. The line is not excused as a whole; only the quoted text is set aside.
#
# Set aside (the data commands):
#   echo, grep/egrep/fgrep: every quoted string except a redirect target.
#   git commit: the quoted message after -m / -am / --message / --message=.
#   a heredoc body, when its command is `cat` printing or writing a data file (.sql,
#   .md, .txt, .rst, .csv, .json, .yaml, .yml, .toml, .log), or `git commit` reading
#   its message from stdin. A body holding `$(`, `${` or a backtick under an unquoted
#   delimiter runs code and is not set aside.
# Commands that may stand beside them, with nothing set aside in them: ls, cat, head,
# tail, wc, git status/log/diff.
# Nothing is set aside, and the line keeps the verdict the rules gave it, when: any
# other command is on the line (a pipe into `sh`, `&& <anything else>`); a quote never
# closes; a double-quoted string holds `$(`, `${` or a backtick; `$'..'`, `$".."`, a
# subshell, a process substitution or a here-string appears; or the line is longer
# than _MASK_MAX_CHARS. A redirect target is judged by the rules as written, so
# `echo hi > "<baseline>"` is still a baseline write.

_MASK_MAX_CHARS = 100_000
_DATA_EXT = (".sql", ".md", ".txt", ".rst", ".csv", ".json", ".yaml", ".yml", ".toml", ".log")
_ECHO_LIKE = frozenset(("echo", "grep", "egrep", "fgrep"))
_PASSIVE = frozenset(("ls", "cat", "head", "tail", "wc"))
_PASSIVE_GIT = frozenset(("status", "log", "diff"))
_MASK_PLAIN = re.compile(r"[^\s'\"\\;&|<>()`$]+")
_MASK_DQ = re.compile(r'"((?:[^"\\]|\\.)*)"', re.S)
_MASK_DELIM = re.compile(r"""'([^']*)'|"([^"]*)"|\\?([^\s;&|<>()'"\\`$]+)""")
_MASK_BLANKS = re.compile(r"[ \t]*")
_MASK_WRITES = ("w", "a")          # operators that put text in a file


class _MWord:
    """One shell word: its pieces as (kind, start, end), kind p plain, s single-quoted,
    d double-quoted (start..end is the content), e a backslash escape. ``op`` is the
    redirect operator ('w' write, 'a' append, 'r' read) when the word is its target."""
    __slots__ = ("pieces", "op")

    def __init__(self, op: str = ""):
        self.pieces: List[Tuple[str, int, int]] = []
        self.op = op


def _msg_flag(w: str) -> bool:
    """``-m``, or a short-option cluster that ends in it (``-am``, ``-sm``)."""
    return len(w) >= 2 and w[0] == "-" and w[1] != "-" and w[-1] == "m" and w[1:].isalpha()


def mask_data_arguments(text: str) -> Optional[str]:
    """``text`` with the data arguments of its commands blanked (see the section
    comment), or None when the line is not made only of commands that take them."""
    n = len(text)
    if n > _MASK_MAX_CHARS:
        return None
    spans: List[Tuple[int, int]] = []
    words: List[_MWord] = []
    pending: List[dict] = []         # heredocs whose body starts at the next newline
    st = {"cur": None, "op": "", "cmd": 0}

    def plain(w: _MWord) -> Optional[str]:
        """The text of a word with no quote or escape in it, else None."""
        if len(w.pieces) == 1 and w.pieces[0][0] == "p":
            return text[w.pieces[0][1]:w.pieces[0][2]]
        return None

    def word() -> _MWord:
        if st["cur"] is None:
            st["cur"] = _MWord(st["op"])
            st["op"] = ""
        return st["cur"]

    def end_word() -> None:
        if st["cur"] is not None:
            words.append(st["cur"])
            st["cur"] = None

    def data_file(w: _MWord) -> bool:
        return "".join(text[s:e] for _, s, e in w.pieces).lower().endswith(_DATA_EXT)

    def quoted_spans(ws: Sequence[_MWord]) -> None:
        for w in ws:
            spans.extend((s, e) for k, s, e in w.pieces if k in "sd")

    def end_command() -> bool:
        """Judge the command that just ended. False: it is not a data command."""
        end_word()
        ws = list(words)
        del words[:]
        st["op"] = ""
        mine = [h for h in pending if h["cmd"] == st["cmd"]]
        st["cmd"] += 1
        args = [w for w in ws if not w.op]
        writes = [w for w in ws if w.op in _MASK_WRITES]
        if not args:
            return not mine
        verb = plain(args[0])
        rest = args[1:]
        if verb == "git":
            # global options come before the subcommand: `git -C x grep "..."`
            k = 0
            while k < len(rest):
                t = plain(rest[k])
                if t in _GIT_OPTS_WITH_VALUE:
                    k += 2
                elif t is not None and t.startswith("-"):
                    k += 1
                else:
                    break
            rest = rest[k:]
        body_ok = False
        if verb in _ECHO_LIKE:
            quoted_spans(rest)
        elif verb == "cat":
            body_ok = all(data_file(w) for w in writes)
        elif verb in _PASSIVE:
            pass
        elif verb == "git" and rest and plain(rest[0]) in _PASSIVE_GIT:
            pass
        elif verb == "git" and rest and plain(rest[0]) == "grep":
            # patterns and pathspecs are data, unless `-O` / `--open-files-in-pager`
            # hands the matches to a program
            if any("".join(text[a:b] for _, a, b in w.pieces).startswith(("-O", "--open"))
                   for w in rest[1:]):
                return False
            quoted_spans(rest[1:])
        elif verb == "git" and rest and plain(rest[0]) == "commit":
            body_ok = True
            take = False
            for w in rest[1:]:
                t = plain(w)
                if take:
                    quoted_spans([w])
                    take = False
                elif t is not None and (t == "--message" or _msg_flag(t)):
                    take = True
                elif (w.pieces and w.pieces[0][0] == "p"
                      and text.startswith("--message=", w.pieces[0][1])):
                    quoted_spans([_sub(w)])
        else:
            return False
        for h in mine:
            h["ok"] = body_ok
        return True

    def _sub(w: _MWord) -> _MWord:
        r = _MWord(w.op)
        r.pieces = w.pieces[1:]
        return r

    def read_bodies(i: int) -> int:
        """Consume the bodies of the pending heredocs, from index ``i`` (the start of
        the line after the newline). Returns the index after the last delimiter line,
        or -1 when a delimiter never comes."""
        for h in pending:
            start = i
            while True:
                j = text.find("\n", i)
                line = text[i:(n if j < 0 else j)]
                if (line.lstrip("\t") if h["tabs"] else line) == h["delim"]:
                    break
                if j < 0:
                    return -1
                i = j + 1
            body = text[start:i]
            if h["ok"] and (h["quoted"] or not ("$(" in body or "`" in body or "${" in body)):
                spans.append((start, i))
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
        del pending[:]
        return i

    i = 0
    while i < n:
        c = text[i]
        if c in " \t" or (c != "\n" and c.isspace()):
            end_word()                       # any other whitespace (CR, NBSP, VT, FF, NEL ...)
            i += 1
        elif c == "\n":
            if not end_command():
                return None
            i += 1
            if pending:
                i = read_bodies(i)
                if i < 0:
                    return None
        elif c == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return None
            word().pieces.append(("s", i + 1, j))
            i = j + 1
        elif c == '"':
            m = _MASK_DQ.match(text, i)
            if not m:
                return None
            body = m.group(1)
            if "`" in body or "$(" in body or "${" in body:
                return None
            word().pieces.append(("d", m.start(1), m.end(1)))
            i = m.end()
        elif c == "\\":
            word().pieces.append(("e", i, min(i + 2, n)))
            i += 2
        elif c in "`()":
            return None
        elif c == "$":
            if text[i + 1:i + 2] in ("(", "'", '"', "{"):
                return None
            word().pieces.append(("p", i, i + 1))
            i += 1
        elif c == ";":
            if not end_command():
                return None
            i += 1
        elif c == "&" and not text.startswith("&>", i):
            if not end_command():
                return None
            i += 2 if text.startswith("&&", i) else 1
        elif c == "|":
            if not end_command():
                return None
            i += 2 if text[i + 1:i + 2] in ("|", "&") else 1
        elif c in "<>&":
            if text.startswith("<<<", i) or text.startswith(("<(", ">("), i):
                return None
            cur = st["cur"]
            if cur is not None and not cur.op and all(
                    k == "p" and text[s:e].isdigit() for k, s, e in cur.pieces):
                st["cur"] = None                          # `2>`: a descriptor number
            else:
                end_word()
            if text.startswith("<<", i):
                i += 2
                tabs = text.startswith("-", i)
                i += 1 if tabs else 0
                i = _MASK_BLANKS.match(text, i).end()
                m = _MASK_DELIM.match(text, i)
                if not m:
                    return None
                quoted = m.group(3) is None or text[i] == "\\"
                pending.append({"cmd": st["cmd"], "delim": next(g for g in m.groups() if g
                                                                is not None),
                                "quoted": quoted, "tabs": tabs, "ok": False})
                i = m.end()
                continue
            if text.startswith("&>>", i):
                st["op"], i = "a", i + 3
            elif text.startswith("&>", i):
                st["op"], i = "w", i + 2
            elif c == ">" and text.startswith(">>", i):
                st["op"], i = "a", i + 2
            elif c == ">":
                i += 2 if text[i + 1:i + 2] in ("|", "&") else 1
                st["op"] = "w"
            elif c == "<":
                i += 2 if text[i + 1:i + 2] in ("&", ">") else 1
                st["op"] = "r"
            else:                                           # a lone `&` was handled above
                return None
        else:
            m = _MASK_PLAIN.match(text, i)
            if m is None:                    # a character no branch above claims: not maskable
                return None
            word().pieces.append(("p", m.start(), m.end()))
            i = m.end()
    if not end_command():
        return None
    out = list(text)
    for s, e in spans:
        for k in range(s, e):
            if out[k] != "\n":
                out[k] = "_"
    return "".join(out)


def check_command(command: str, rules: Optional[Sequence[Rule]] = None,
                  ctx: Optional[Context] = None) -> Optional[Rule]:
    """The first rule the command trips, or None if it may run."""
    if not command:
        return None
    rules = DEFAULT_RULES if rules is None else rules
    ctx = ctx or Context()
    # A backslash-newline is removed by the shell before it reads a word, so
    # `curl \<nl>x | sh` is `curl x | sh`. Only the joined text is judged (judging the
    # original too would block `su \<nl>-c cat`, which is `su -c cat`). A backslash
    # that is itself escaped (`\\<nl>`) is not a continuation and stays a newline.
    # The text with quotes and backslash escapes removed word by word is judged as
    # well, so `r\m`, `"rm"` and `bl""ess` are read as the words they spell.
    joined = _JOIN.sub(r"\1", command)
    variants = [joined]
    plain = _unquote_words(joined)
    if plain != joined:
        variants.append(plain)
    try:
        hit, used = None, command
        for r in rules:
            for v in variants:
                if r.hit(v, ctx):
                    hit, used = r, v
                    break
            if hit is not None:
                break
    except WorkBudgetExceeded as e:
        # Too large to judge in bounded time, and a hook that times out lets the
        # call through: refuse. The read-only allowlist does not excuse this.
        return Rule("work-budget-exceeded",
                    f"command cannot be judged within the work budget ({e.what}); "
                    f"refused rather than left to time out", "HIGH")
    if hit is None:
        return None
    if not _ESCAPES.search(used):
        segs = segments(used)
        if (segs and all(any(re.search(p, s) for p in SAFE_PREFIXES) for s in segs)
                and not any(_ALLOWLIST_BLOCKS(s) for s in segs)):
            return None
    # Second chance: the line is made only of commands whose quoted arguments are
    # data. Judge it again with that text blanked (mask_data_arguments).
    masked = mask_data_arguments(joined)
    if masked is None or masked == joined:
        return hit
    mvariants = [masked]
    mplain = _unquote_words(masked)
    if mplain != masked:
        mvariants.append(mplain)
    try:
        for r in rules:
            if any(r.hit(v, ctx) for v in mvariants):
                return r
    except WorkBudgetExceeded as e:
        return Rule("work-budget-exceeded",
                    f"command cannot be judged within the work budget ({e.what}); "
                    f"refused rather than left to time out", "HIGH")
    return None


#: Tool names whose ``tool_input.command`` is judged as shell text. Claude Code has other
#: tools that run shell text (PowerShell on Windows, possibly others); this kit has not
#: verified their input shapes, so only ``Bash`` is judged unless the project lists more
#: in ``commands.shell_tools`` AND registers the guard for them (``install --shell-tool``).
DEFAULT_SHELL_TOOLS: Tuple[str, ...] = ("Bash",)


def shell_tools(cfg: Optional[dict]) -> Tuple[str, ...]:
    """``Bash`` plus the valid names in ``commands.shell_tools``. Bash cannot be dropped."""
    extra = cfgmod.str_list(cfgmod.section(cfg or {}, "commands"), "shell_tools")
    return DEFAULT_SHELL_TOOLS + tuple(t.strip() for t in extra
                                       if t.strip() not in DEFAULT_SHELL_TOOLS)


def run(payload: Optional[dict], oversized: bool, cfg: dict) -> int:
    """Hook entry: decide on one PreToolUse payload. Returns the exit code."""
    if oversized:
        return hookio.deny(f"BLOCKED: {hookio.refusal_reason(oversized)}, so the "
                           "command could not be examined.")
    if payload is None:
        return hookio.EXIT_ALLOW
    tool = payload.get("tool_name")
    ti = hookio.tool_input(payload)
    sql_tools = cfgmod.section(cfg, "commands").get("sql_tools") or {}
    is_sql = False
    if tool in shell_tools(cfg):
        command = ti.get("command")
    elif isinstance(sql_tools, dict) and tool in sql_tools:
        command = ti.get(str(sql_tools[tool]))
        is_sql = True
    else:
        return hookio.EXIT_ALLOW
    if not isinstance(command, str):
        return hookio.EXIT_ALLOW
    rules, ctx, _ = active_rules(cfg)            # entry warnings are printed once, at load
    if is_sql:
        ctx = replace(ctx, sql_input=True)
    hit = check_command(command, rules, ctx)
    if hit is None:
        return hookio.EXIT_ALLOW
    return hookio.deny(
        f"BLOCKED [{hit.severity}] {hit.description} (rule {hit.id}). "
        f"Command: {command[:200]}. If this is really intended, ask the user to run "
        f"it themselves.")
