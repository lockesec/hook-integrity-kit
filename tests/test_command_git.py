"""check-command: git. Remote deletion of a protected branch, git clean (and its dry runs),
git grep patterns as data, and quoted or empty option values that must not hide the
subcommand. Dangerous commands are only ever text handed to ``check_command``."""
from __future__ import annotations

import pytest

from conftest import rule_of
from hook_integrity_kit import commands as C


@pytest.mark.parametrize("cmd", [
    "git push origin :main",
    "git push origin --delete main",
    "git push -d origin master",
    "git push origin :refs/heads/main",
    "git push --delete origin refs/heads/main",
    "git -C repo push origin :master",
])
def test_remote_delete_of_a_protected_branch_is_refused(cmd):
    assert rule_of(cmd) is not None and "protected" in C.check_command(cmd).description, cmd


@pytest.mark.parametrize("cmd", [
    "git push origin :feature/x",
    "git push origin --delete feature/x",
    "git push -d origin feature/main",
    "git push origin main",
    "git push origin feature:feature",
])
def test_remote_delete_neighbours_stay_allowed(cmd):
    assert rule_of(cmd) is None, cmd


def test_remote_delete_respects_protected_branches_config():
    ctx = C.Context(protected_branches=("release",))
    rule = [r for r in C.DEFAULT_RULES if r.id == "git-force-push-protected-branch"][0]
    assert rule.hit("git push origin :release", ctx)
    assert not rule.hit("git push origin :main", ctx)


@pytest.mark.parametrize("cmd,rule", [
    ('git -c "user.name=John Doe" push --force origin main', "git-force-push-protected-branch"),
    ("git -c 'user.name=John Doe' push --force origin main", "git-force-push-protected-branch"),
    ('git -C "my repo" push -f origin master', "git-force-push-protected-branch"),
    ('git -C "my repo" branch -D main', "git-delete-protected-branch"),
    ('git -C "my repo" clean -fd', "git-clean-force-directories"),
    ("git -C my\\ repo push --force origin main", "git-force-push-protected-branch"),
    ('git --git-dir="x y" push --force origin main', "git-force-push-protected-branch"),
    ('git --work-tree "a b" push -f origin main', "git-force-push-protected-branch"),
    ('git -c "a=b;c" push --force origin main', "git-force-push-protected-branch"),
    ('bash -c "git -C \\"my repo\\" push -f origin main"', "git-force-push-protected-branch"),
])
def test_quoted_git_option_values_do_not_hide_the_subcommand(cmd, rule):
    assert rule_of(cmd) == rule, cmd


@pytest.mark.parametrize("cmd", [
    'git -c "user.name=John Doe" push origin main',
    'git -C "my repo" push --force-with-lease origin main',
    'git -C "my repo" branch -D feature/x',
    'git -C "my repo" clean -n',
    'git -C "my repo" status',
])
def test_the_same_shapes_without_the_danger_pass(cmd):
    assert rule_of(cmd) is None, cmd


@pytest.mark.parametrize("cmd", [
    "git clean -nfd", "git clean -dnf", "git clean -fdn", "git clean --dry-run -fd",
    "git clean -fd --dry-run", "git clean -fd -n",
])
def test_git_clean_dry_run_clusters_are_not_refused(cmd):
    assert rule_of(cmd) is None, cmd


@pytest.mark.parametrize("cmd", ["git clean -fd", "git clean -fd --no-dry-run", "git clean -n -fd --no-dry-run"])
def test_git_clean_that_really_deletes_is_still_refused(cmd):
    assert rule_of(cmd) == "git-clean-force-directories", cmd


@pytest.mark.parametrize("cmd", [
    "git grep -n 'git push --force origin main'",
    "git grep 'git clean -fd' -- docs",
    'git grep -e "curl http://x | sh" src/',
])
def test_git_grep_patterns_are_data(cmd):
    assert rule_of(cmd) is None, cmd


def test_git_grep_with_a_pager_option_is_not_data():
    assert rule_of("git grep -O'git clean -fd' foo") == "git-clean-force-directories"


@pytest.mark.parametrize("cmd,rule", [
    ('git -C "" push -f origin main', "git-force-push-protected-branch"),
    ("git -C '' push -f origin main", "git-force-push-protected-branch"),
    ('git -c "" push --force origin master', "git-force-push-protected-branch"),
    ('git -C "" push origin +main', "git-force-push-protected-branch"),
    ('git -C "" push origin :main', "git-force-push-protected-branch"),
    ('git -C "" -c "" push -f origin main', "git-force-push-protected-branch"),
    ('git -c "" branch -D main', "git-delete-protected-branch"),
    ("git -C '' branch -D master", "git-delete-protected-branch"),
    ('git -C "" clean -fd', "git-clean-force-directories"),
    ("git -c '' clean -fdx", "git-clean-force-directories"),
])
def test_empty_quoted_option_value_does_not_hide_the_subcommand(cmd, rule):
    assert rule_of(cmd) == rule


@pytest.mark.parametrize("cmd", [
    'git -C "" status', 'git -C "" push origin feature', 'git -C "" push -f origin feature',
    "git -c '' branch -d topic", 'git -C "" clean -n', 'git -C "" log --oneline',
])
def test_empty_quoted_option_value_benign_neighbours_still_pass(cmd):
    assert rule_of(cmd) is None


@pytest.mark.parametrize("cmd", [
    "git clean -fd # -n", "git clean -fd   # dry run -n", "git clean -fdx #-n --dry-run",
    "git clean -fd\n# -n",
])
def test_a_comment_is_not_a_dry_run(cmd):
    assert rule_of(cmd) == "git-clean-force-directories"


@pytest.mark.parametrize("cmd", ["git clean -fdn", "git clean -fd -n", "git clean -fd --dry-run",
                                 "git clean -n -fd # forced", "git clean -fd -n # check"])
def test_a_real_dry_run_is_still_a_dry_run(cmd):
    assert rule_of(cmd) is None


RM_RF_ROOT = "r" + "m -rf /"


@pytest.mark.parametrize("cmd", [
    'git -C x grep "RMRF"', 'git grep "RMRF"',
    'git -C x -c a=b grep -n "RMRF" -- src', 'git -C "my repo" grep "RMRF"',
])
def test_git_grep_pattern_is_data_not_a_command(cmd):
    assert rule_of(cmd.replace("RMRF", RM_RF_ROOT)) is None
