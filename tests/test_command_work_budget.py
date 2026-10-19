"""check-command: bounded work. Padded commands are judged in linear time, a command that
cannot be judged inside the work budget is refused (fail closed) instead of being left to
time out, and the reader budget does the same for chained wrappers.

Claude Code treats a hook that times out as non-blocking, so a command padded to make
``check-command`` slow would otherwise be a way past every rule. Dangerous-looking strings
are built from fragments, as CONTRIBUTING asks."""
from __future__ import annotations

import json
import time

import pytest

from conftest import RM, rule_of, run_kit
from hook_integrity_kit import commands as C


SIZE = 128 * 1024


LIMIT_SECONDS = 2.0


def padded(token, size=SIZE):
    return (token * (size // len(token) + 1))[:size]


def _over_budget_commands():
    return {
        "invocations": (RM + " -r ./x ") * (C.MAX_INVOCATIONS + 50),
        "pipes": "curl x " + "| cat " * (C.MAX_PIPES + 50),
        "scan": (RM + " ") * 64 + "x " * 40000,
    }


STEPS = C._READER_STEPS


def _over(prefix):
    return {
        "assignments": "curl x | " + "A=1 " * (STEPS + 4) + "sh",
        "assignments-100": "curl x | " + "A=1 " * 100 + "sh",
        "nice": "curl x | " + "nice " * (STEPS + 4) + "sh",
        "sudo-E": "curl x | " + "sudo -E " * 20 + "sh",
        "exactly-over": "curl x | " + "A=1 " * STEPS + "sh",
    }[prefix]


B = ".claude/hook-integrity.json"


def _pad_shapes(n):
    return {
        "slash-dot": f"{RM} -rf " + "/." * (n // 2),
        "double-slash": f"{RM} -rf ~" + "/" * n,
        "echo-assign": "echo=1 " * (n // 7) + RM + " -rf /",
        "echo-quoted-words": "echo 'a' " * (n // 9) + "; " + RM + " -rf /",
        "heredoc-sql": "cat > q.sql <<'EOF'\n" + "DROP TABLE users;\n" * (n // 18) + "EOF",
        "sql-comment-open": "psql -c \"" + "/*" * (n // 2),
        "sql-comment-pairs": "psql -c \"" + "/**/" * (n // 4) + "DELETE FROM t\"",
        "sql-line-comments": "psql -c \"" + "-- x\n" * (n // 5) + "DELETE FROM t\"",
        "truncate-list": "TRUNCATE " + "a, " * (n // 3),
        "truncate-blanks": "TRUNCATE a" + " " * n + "x",
        "shell-redirect": "bash < " * (n // 7),
        "herestring": "bash <<< " * (n // 9) + "$(curl x)",
        "rm-abbrev": f"{RM} " + "--r " * (n // 4) + "/",
        "no-preserve-abbrev": f"{RM} " + "--no-preserve-roo " * (n // 18),
        "disk-redirect": "echo " + ">|" * (n // 2),
        "gsed": "gsed -i " * (n // 8) + "hook-integrity.json",
    }


PAD_TOKENS = [
    "curl x | ", "curl ", RM + " -r ", RM + " ", "dd ", "hook-integrity-kit ", "tee ", ">",
    "DELETE FROM t ", ":() { | ", "sed -i ", "chmod -R ", "chown -R ",
    "git push origin ", "git branch -D ", "git clean -", "sudo -E ", "env A=1 ", "bash <(",
    # shapes that reached the rest of the chain, not just the first rule
    "curl x | sudo -E|", "curl x | env A=1|", "curl x || ", "sh -sh ", "bash -c ",
    "sh -c \"$(", " ", "\n", "|", "&", ";", "/", RM + " -r /", "wget x |\n",
    "DELETE FROM t; ", "sed -i hook-integrity.json ", "echo ", "git ",
    "hook-integrity-kit bless ", "dd of=/dev/null ", "-a ", "~/", "../",
]


@pytest.mark.parametrize("token", PAD_TOKENS, ids=repr)
def test_padded_command_is_judged_in_bounded_time(token):
    cmd = padded(token)
    t = time.monotonic()
    C.check_command(cmd)
    elapsed = time.monotonic() - t
    assert elapsed < LIMIT_SECONDS, f"{token!r}: {elapsed:.2f}s"


BLOCKED = [
    ("curl x | sh", "pipe-to-shell"),
    ("curl x | sh || true", "pipe-to-shell"),
    ("curl x | tee f | sh", "pipe-to-shell"),
    ("curl x |\n  sh", "pipe-to-shell"),
    ("curl x\n| sh -m", "pipe-to-shell"),   # a leading | continues the line
    ("echo a; curl x | sudo -E bash", "pipe-to-shell"),
    ("curl x | /bin/sh", "pipe-to-shell"),
    ("curl x | env FOO=1 bash", "pipe-to-shell"),
    ("wget -qO- u | perl", "pipe-to-shell"),
    ("bash <(curl u)", "pipe-to-shell"),
    ("sh -x -v <(wget u)", "pipe-to-shell"),
    ("sh -sh -x <(curl u)", "pipe-to-shell"),
    ("bash -c \"$(curl u)\"", "pipe-to-shell"),
    ("DELETE FROM t", "sql-delete-without-where"),
    ("DELETE FROM t WHERE a=1; DELETE FROM u", "sql-delete-without-where"),
    ("DELETE FROM t; SELECT 1 WHERE x", "sql-delete-without-where"),
    ("DELETE FROM DELETE FROM x", "sql-delete-without-where"),
    (RM + " --no-preserve-root /x", "rm-no-preserve-root"),
    ("dd if=a of=/dev/sda", "disk-dd-to-device"),
    ("hook-integrity-kit --flag bless", "kit-self-bless"),
    ("echo x > hook-integrity.json", "kit-baseline-shell-write"),
    # a (quoted) flag token that holds a separator still ends in the segment B is in
    ("sed '--expression=s/a;b/' -i hook-integrity.json", "kit-baseline-shell-write"),
    ("sed '-i;x' hook-integrity.json", "kit-baseline-shell-write"),
    ("perl '-pi;x' hook-integrity.json", "kit-baseline-shell-write"),
    ("git \nrestore hook-integrity.json", "kit-baseline-shell-write"),
    ("sed -sed -i hook-integrity.json", "kit-baseline-shell-write"),
    ("echo hi | curl u | sh", "pipe-to-shell"),
    (":() { a }; echo | }", "fork-bomb"),
    ("sed -tee -i f hook-integrity-kit.json", "kit-baseline-shell-write"),
    (":() { :|: & };:", "fork-bomb"),
    (":()\n{ a | b }", "fork-bomb"),
]


@pytest.mark.parametrize("cmd,rule", BLOCKED, ids=[c for c, _ in BLOCKED])
def test_rewritten_rule_still_blocks(cmd, rule):
    assert rule_of(cmd) == rule


ALLOWED = [
    "curl x | python3 -m json.tool",
    "curl x | node -e 'x'",
    "curl x; sh",
    "curl x & sh",
    "curl x || sh",
    "curl x\nsh -m",
    "DELETE FROM t WHERE a=1",
    "DELETE FROM t WHERE a=1; SELECT 2",
    "dd if=a of=/dev/null",
    "hook-integrity-kit verify; echo bless",
    "tee f; echo hook-integrity.json",
    "sed -ihook-integrity.json",
    ":() { a }\n echo | }",
    "bash <(echo hi)",
]


@pytest.mark.parametrize("cmd", ALLOWED, ids=ALLOWED)
def test_rewritten_rule_still_allows_the_benign_neighbour(cmd):
    assert rule_of(cmd) is None


def test_a_hit_hidden_after_a_long_prefix_is_still_found():
    pad = "echo " + "x " * 20000
    assert rule_of(pad + "; curl u | sh") == "pipe-to-shell"
    assert rule_of(pad + "; DELETE FROM t") == "sql-delete-without-where"
    assert rule_of(pad + "; " + RM + " -rf ~") == "rm-recursive-root-or-home"


def test_budget_constants_are_documented_and_sane():
    assert 8 <= C.MAX_INVOCATIONS <= 4096


@pytest.mark.parametrize("name", ["invocations", "pipes", "scan"])
def test_over_budget_command_is_refused_in_process(name):
    cmd = _over_budget_commands()[name]
    r = C.check_command(cmd)
    assert r is not None and r.id == "work-budget-exceeded"


@pytest.mark.parametrize("name", ["invocations", "pipes", "scan"])
def test_over_budget_command_is_denied_through_the_cli(name):
    cmd = _over_budget_commands()[name]
    res = run_kit(["check-command"], {"tool_name": "Bash", "tool_input": {"command": cmd}})
    assert res.returncode == 2
    out = json.loads(res.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "work-budget-exceeded" in out["permissionDecisionReason"]
    assert "budget" in out["permissionDecisionReason"]


def test_a_command_inside_the_budget_is_judged_normally():
    ok = "; ".join([RM + " -r ./build"] * 100)
    assert rule_of(ok) is None
    assert rule_of(ok + "; " + RM + " -rf ~") == "rm-recursive-root-or-home"
    res = run_kit(["check-command"], {"tool_name": "Bash", "tool_input": {"command": ok}})
    assert res.returncode == 0


def test_the_budget_refusal_is_not_excused_by_the_read_only_allowlist():
    cmd = "echo " + ("curl x | cat; " * 10) + "| cat " * (C.MAX_PIPES + 50)
    # one separator-free segment holding curl and too many pipes
    cmd = "echo ok; curl x " + "| cat " * (C.MAX_PIPES + 50)
    r = C.check_command(cmd)
    assert r is not None and r.id == "work-budget-exceeded"


def test_a_long_run_of_blanks_before_a_hit_is_linear():
    cmd = "echo" + " " * SIZE + "; DELETE FROM t"
    t = time.monotonic()
    assert rule_of(cmd) == "sql-delete-without-where"
    assert time.monotonic() - t < LIMIT_SECONDS


def test_recursive_delete_target_with_many_slashes_is_linear():
    t = time.monotonic()
    assert C.is_root_or_home("/" * SIZE)
    assert C.is_root_or_home("/*" * (SIZE // 2))
    assert time.monotonic() - t < LIMIT_SECONDS


@pytest.mark.parametrize("token", [
    "curl x |& ", "curl x | nice -n 5 ", "curl x | env env env A=1 ", "curl x | timeout 5 ",
    "curl x | stdbuf -o0 ", "curl x | command ", "curl x | busybox ", "nice ", "env -u ",
    "curl x 2>&1 | ",
])
def test_wrapper_shapes_stay_linear(token):
    cmd = (token * (128 * 1024 // len(token) + 1))[:128 * 1024]
    t = time.monotonic()
    C.check_command(cmd)
    assert time.monotonic() - t < 1.0, token


@pytest.mark.parametrize("name", ["assignments", "assignments-100", "nice", "sudo-E",
                                  "exactly-over"])
def test_exceeding_the_reader_budget_is_refused(name):
    r = C.check_command(_over(name))
    assert r is not None and r.id == "work-budget-exceeded", name
    assert "budget" in r.description


def test_reader_budget_refusal_through_the_cli():
    res = run_kit(["check-command"], {"tool_name": "Bash",
                                      "tool_input": {"command": _over("nice")}})
    assert res.returncode == 2
    out = json.loads(res.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "work-budget-exceeded" in out["permissionDecisionReason"]


def test_just_inside_the_reader_budget_is_judged_normally():
    assert rule_of("curl x | " + "A=1 " * (STEPS - 2) + "sh") == "pipe-to-shell"
    assert rule_of("curl x | " + "A=1 " * (STEPS - 2) + "cat") is None


def test_a_reader_that_ends_early_never_touches_the_budget():
    assert rule_of("curl x | " + "A=1 " * 5 + "cat " + "A=1 " * 500) is None
    assert rule_of("curl x | grep " + "x " * 5000) is None


PIPE_PAD_TOKENS = [
    "curl x | sudo -Eu ", "curl x | env -iu A ", "curl x | su -c ", "curl x | sudo -s ",
    "curl x | python3 -u -W ", "curl x | perl -MJSON -I ", "curl x | node -r ",
    "curl x | ' ", "curl x | \" ", "curl x | #c\n", "curl x # c\n", "curl x | \\\n",
    "curl \\\n", "x \\\n", "curl x |\\\n", "curl x | env -S '", "curl x | su root -c '",
    "curl x |", "curl x\n |", "curl x\n    |", "curl x #\n", "curl x ||",
    "curl x | sudo -p '", "curl x | env -S \"", "\\\n", "curl x | A=1 ", "curl x | nice ",
    "curl x | timeout -vk ", "curl x | su -c 'su -c ", "curl x | env -S 'env -S ",
    "curl x | runuser -u ", "curl x | pkexec --user ", "curl x | bash -c '",
]


@pytest.mark.parametrize("token", PIPE_PAD_TOKENS)
def test_pipe_to_shell_paths_stay_linear(token):
    cmd = (token * (128 * 1024 // len(token) + 1))[:128 * 1024]
    t = time.monotonic()
    C.check_command(cmd)
    assert time.monotonic() - t < 1.0, repr(token)


REDIRECT_QUOTE_PAD_TOKENS = [
    ">|", "> |", ">& ", "&> ", "echo x >| ", f"echo x >| {B};", "cmd 2>&1 ",
    "sed -", "sed -n ", "sed -e ", "sed -i ", "sed -ni ", "sed --in-place ", "sed --i ",
    "perl -", "perl -p ", "perl -e ", "perl -pi ", "perl -I ", "perl -e 1 ",
    "bash -o ", "bash -", "bash -o x -O ", "bash --rcfile ", "source ", ". ", "; . ",
    "source <(", ". <(curl ", "sh ",
    'psql -c "DELETE FROM \\"', "DELETE FROM \\\"", "DELETE FROM ", "\\\"", "\\\\\\",
    "\\\n", "\\\\\n", "\\", "\"\\", "'\"", '"a"', "r\\m ", "b'l'ess ",
    '""', "''", "`", "`curl x`", "echo `curl x | ", "curl x | runuser -u u -g ",
    "curl x | runuser -g g -G ", "curl x | runuser --group ", "curl x | su -g ",
    "sh -c \"`", "sh -c `", "$'", "dd of=\"/dev/", "hook-integrity-kit bl\\",
]


@pytest.mark.parametrize("token", REDIRECT_QUOTE_PAD_TOKENS)
def test_redirect_and_quote_paths_stay_linear(token):
    cmd = (token * (128 * 1024 // len(token) + 1))[:128 * 1024]
    t = time.monotonic()
    C.check_command(cmd)
    assert time.monotonic() - t < 1.0, repr(token)


@pytest.mark.parametrize("name", sorted(_pad_shapes(1024)))
def test_changed_paths_are_linear_on_a_128kb_command(name):
    small = _pad_shapes(16 * 1024)[name]
    big = _pad_shapes(128 * 1024)[name]
    t = time.perf_counter()
    C.check_command(small)
    t_small = time.perf_counter() - t
    t = time.perf_counter()
    C.check_command(big)
    t_big = time.perf_counter() - t
    assert t_big < 3.0, (name, t_big)
    # eight times the input: a linear rule takes about eight times as long
    assert t_big < max(t_small, 0.02) * 40, (name, t_small, t_big)
