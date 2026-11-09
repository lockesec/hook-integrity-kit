"""Shapes that made the second-chance mask blank a real command, found by a danger review.
Strings only: nothing here is run."""
import pytest
from hook_integrity_kit.commands import check_command

BLESS = "hook-integrity-kit bless"
PUSH = "git push -f origin main"


@pytest.mark.parametrize("command", [
    f"echo x # don't\n{BLESS}\necho it's",
    f"echo x # don't\n{PUSH}\necho it's",
    f"echo hi # '\n{BLESS}\n# '",
    f'echo hi # "\n{BLESS}\n# "',
    f"cat /dev/null # <<'EOF'\n{BLESS}\nEOF",
    f"# don't\n{BLESS}\n# it's",
])
def test_a_quote_in_a_comment_cannot_blank_the_next_line(command):
    assert check_command(command) is not None, command


def test_a_heredoc_delimiter_is_the_whole_word():
    # The shell ends this body at the line AB. Reading the delimiter as A would blank the command.
    assert check_command(f"cat <<'A'B\nx\nAB\n{BLESS}\nA\n") is not None


@pytest.mark.parametrize("command", [
    "git grep -nO'sh -c evil' x",
    "git grep -O'sh -c evil' x",
    "git grep --open='sh -c evil' x",
    "git grep --op='sh -c evil' x",
])
def test_every_spelling_of_the_grep_pager_is_not_data(command):
    assert check_command(command + f" ; {BLESS}") is not None
    from hook_integrity_kit.commands import mask_data_arguments
    assert mask_data_arguments(command) is None, command


@pytest.mark.parametrize("command", [
    "python3 -c \"from hook_integrity_kit.cli import main; main(['bless'])\"",
    "python -c 'import hook_integrity_kit.cli as c; c.main([\"bless\"])'",
])
def test_the_library_route_to_bless_is_refused(command):
    rule = check_command(command)
    assert rule is not None and rule.id == "kit-self-bless"


@pytest.mark.parametrize("command", [
    "echo 'hook-integrity-kit bless'",
    "git commit -m 'run hook-integrity-kit bless after review'",
    "git grep -n 'hook-integrity-kit bless' docs",
    "echo x # a plain comment",
    "python3 -c \"import hook_integrity_kit; print(hook_integrity_kit.__version__)\"",
    "ls # don't",
])
def test_these_stay_allowed(command):
    assert check_command(command) is None, command
