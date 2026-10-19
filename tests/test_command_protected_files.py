"""check-command: commands that write the baseline, the kit config or a settings file. Every
redirect form, in-place sed/perl, git output options, git archive/bundle, links made through
Bash, and re-blessing through Bash, with the reads that must stay allowed.

Dangerous commands are only ever text handed to ``check_command``."""
from __future__ import annotations

import pytest

from conftest import rule_of
from hook_integrity_kit import commands as C


B = ".claude/hook-integrity.json"


BL = ".claude/hook-integrity.json"


REDIRECTS = [
    f"echo x >| {B}", f"echo x >|{B}", f"echo x 1>| {B}", f"echo x &> {B}",
    f"echo x &>> {B}", f"echo x >& {B}", f"echo x 1> {B}", f"echo x 2> {B}",
    f"echo x 2>> {B}", f"exec 3<> {B}", f"echo x >{B}", f"echo x >> {B}",
    f"echo x 2>&1 > {B}", f"echo x >| {B} 2>&1", f"cmd 2>&1 >| {B}",
    f"echo x >|\t{B}",
]


@pytest.mark.parametrize("cmd", REDIRECTS)
def test_every_redirect_form_to_the_baseline_is_refused(cmd):
    assert rule_of(cmd) == "kit-baseline-shell-write", cmd


REDIRECT_NEIGHBOURS = [
    f"cat {B}", f"git diff {B}", f"echo x >&2 {B}", f"echo x 2>&1 | cat {B}",
    f"echo x >| out.txt; cat {B}", f"cat {B} >| out.txt", f"cat {B} 2>&1",
    f"cat {B} &> out.txt", f"echo x >&2; echo {B}",
]


@pytest.mark.parametrize("cmd", REDIRECT_NEIGHBOURS)
def test_reading_the_baseline_stays_allowed(cmd):
    assert rule_of(cmd) is None, cmd


PERL_INPLACE = [
    f"perl -p -i -e 1 {B}", f"perl -e 1 -i {B}", f"perl -pi -e 1 {B}",
    f"perl -i.bak -pe 1 {B}", f"perl -pi.bak -e 1 {B}", f"perl -lpi -e 1 {B}",
    f"perl -0pi -e 1 {B}", f"perl -i -ne print {B}", f"perl -MFoo -i -e 1 {B}",
    f"perl -I lib -pi -e 1 {B}", f"perl -wpi -e 1 {B}", f"perl -w -p -i.orig -e 1 {B}",
    f"perl -e 1 -pi {B}", f"perl -i {B}", f"perl -ne print -i {B}",
]


SED_INPLACE = [
    f"sed -Ei s/a/b/ {B}", f"sed -ri s/a/b/ {B}", f"sed --in-place=.b s/a/b/ {B}",
    f"sed --in-place s/a/b/ {B}", f"sed -n -i p {B}", f"sed -ni p {B}",
    f"sed -i.bak s/a/b/ {B}", f"sed -e s/a/b/ -i {B}", f"sed s/a/b/ -i {B}",
    f"sed -E -i -e s/a/b/ {B}", f"sed --i s/a/b/ {B}", f"sed -s -i s/a/b/ {B}",
    f"sed -nEi.b p {B}", f"sudo sed -i s/a/b/ {B}", f"sed -ie s/a/b/ {B}",
    f"sed -i -- s/a/b/ {B}", f"sed --in-pl s/a/b/ {B}", f"sed -n s/a/b/ {B} -i",
    f"sed -zi s/a/b/ {B}", f"sed -f x.sed -i {B}",
]


@pytest.mark.parametrize("cmd", SED_INPLACE + PERL_INPLACE)
def test_in_place_edit_of_the_baseline_is_refused(cmd):
    assert rule_of(cmd) == "kit-baseline-shell-write", cmd


PERL_READS = [
    f"perl -ne print {B}", f"perl -e print {B}", f"perl -pe 1 {B}",
    f"perl -e 'print \"i\"' {B}", f"perl -MList::Util=first -e 1 {B}",
    f"perl -wne print {B}", f"perl -I lib -ne print {B}", f"perl -e 1 {B} -i",
    f"perl script.pl -i {B}", f"perl -MIO -e 1 {B}", f"perl -e i {B}",
    f"perl -ne print {B}; perl -pi -e 1 other",
]


SED_READS = [
    f"sed -n p {B}", f"sed -e s/a/b/ {B}", f"sed -E s/a/b/ {B}", f"sed -ne p {B}",
    f"sed -e s/i/j/ {B}", f"sed -n -e p {B}", f"sed --expression=s/a/b/ {B}",
    f"sed --quiet p {B}", f"sed -f i.sed {B}", f"sed -nf i.sed {B}", f"sed -l 5 p {B}",
    f"sed -s p {B}", f"sed -e -i {B}", f"sed --silent p {B}", f"sed --separate p {B}",
    f"sed -i s/a/b/ other.txt; cat {B}", f"sed -n p -- {B}", f"sed -E p {B}",
]


@pytest.mark.parametrize("cmd", SED_READS + PERL_READS)
def test_reading_the_baseline_with_sed_or_perl_stays_allowed(cmd):
    assert rule_of(cmd) is None, cmd


def test_gsed_in_place_on_the_baseline_is_refused_like_sed():
    assert rule_of(f"gsed -i p {BL}") == "kit-baseline-shell-write"
    assert rule_of(f"gsed -n p {BL}") is None
    assert rule_of(f"sed -i p {BL}") == "kit-baseline-shell-write"


def test_git_diff_output_to_the_baseline_is_a_baseline_write():
    assert rule_of("git diff --output=.claude/hook-integrity.json HEAD~1") == "kit-baseline-shell-write"
    assert rule_of("git log --output .claude/hook-integrity.json") == "kit-baseline-shell-write"
    assert rule_of("git diff HEAD~1") is None
    assert rule_of("git log --grep='x' -p") is None


@pytest.mark.parametrize("cmd", [
    "ln .claude/settings.local.json notes.txt", "ln .claude/settings.json notes.txt",
    "ln -s .claude/settings.local.json notes.txt", "ln -f .claude/settings.json n",
    "ln notes.txt .claude/settings.local.json", 'ln ".claude/settings.json" n',
    "link .claude/settings.json n", "cp -l .claude/settings.json n",
    "cp -al .claude/settings.local.json n", "cp --link .claude/settings.json n",
    "ln /work/proj/.claude/Settings.JSON n",
])
def test_linking_a_settings_file_through_bash_is_refused(cmd):
    assert rule_of(cmd) == "kit-settings-link"


@pytest.mark.parametrize("cmd", [
    "ln notes.txt other.txt", "ln -s ../a b", "cp .claude/settings.json backup.json",
    "cp -a a b", "cat .claude/settings.json", "link a b", "ln -s .claude/hooks h",
])
def test_ordinary_links_and_copies_are_not_refused_as_settings_links(cmd):
    assert rule_of(cmd) is None


@pytest.mark.parametrize("cmd", [
    "git archive -o .claude/hook-integrity.json HEAD",
    "git archive HEAD -o .claude/hook-integrity.json",
    "git archive --output .claude/hook-integrity.json HEAD",
    "git archive --output=.claude/hook-integrity.json HEAD",
    "git archive -o.claude/hook-integrity.json HEAD",
    "git archive -o .claude/hook-integrity-kit.json HEAD",
    "git bundle create .claude/hook-integrity.json HEAD",
    "git -C x bundle create .claude/hook-integrity.json --all",
])
def test_git_archive_and_bundle_cannot_write_the_baseline_or_config(cmd):
    assert rule_of(cmd) == "kit-baseline-shell-write"


@pytest.mark.parametrize("cmd", [
    "git archive -o out.tar HEAD .claude/hook-integrity.json",
    "git archive HEAD -- .claude/hook-integrity.json",
    "git bundle create out.bundle HEAD", "git bundle verify .claude/hook-integrity.json",
])
def test_git_archive_and_bundle_reading_the_baseline_are_not_writes(cmd):
    assert rule_of(cmd) is None


@pytest.mark.parametrize("cmd", [f"git archive --o={BL} HEAD", f"git archive --ou {BL} HEAD",
                                 f"git bundle create -q {BL} --all"])
def test_git_archive_abbreviation_and_bundle_options_write_the_baseline(cmd):
    r = C.check_command(cmd)
    assert r is not None and r.id == "kit-baseline-shell-write"


@pytest.mark.parametrize("cmd", [f"git archive HEAD -- {BL}", "git bundle create -q out.bundle --all",
                                 "git archive --o=out.tar HEAD"])
def test_git_archive_benign_neighbours_stay_quiet(cmd):
    assert C.check_command(cmd) is None


@pytest.mark.parametrize("command", [
    "hook-integrity-kit bless",
    "python3 -m hook_integrity_kit bless --root .",
    "/opt/venv/bin/hook-integrity-kit bless",
    "cd /x && hook-integrity-kit bless",
    "printf '{}' > .claude/hook-integrity.json",
    "echo x >> .claude/hook-integrity.json",
    "cp /tmp/b.json .claude/hook-integrity.json",
    "mv /tmp/b.json .claude/hook-integrity.json",
    "ln -sf /tmp/b.json .claude/hook-integrity.json",
    "tee .claude/hook-integrity.json < /tmp/b",
    "sed -i s/a/b/ .claude/hook-integrity.json",
    "rm .claude/hook-integrity.json",
    "git checkout HEAD~3 -- .claude/hook-integrity.json",
    "echo '{}' > .claude/hook-integrity-kit.json",
])
def test_self_bless_and_baseline_writes_through_bash_are_blocked(command):
    hit = C.check_command(command)
    assert hit is not None, command


@pytest.mark.parametrize("command", [
    "hook-integrity-kit verify",
    "python3 -m hook_integrity_kit verify --json",
    "cat .claude/hook-integrity.json",
    "git diff .claude/hook-integrity.json",
    "git add .claude/hook-integrity.json",
    "grep bless README.md",
])
def test_reading_the_baseline_and_verifying_still_run(command):
    assert C.check_command(command) is None, command
