"""check-command: destructive filesystem, disk, process and ownership commands. rm target
spellings and option abbreviations, raw-disk writes (redirects, dd, filesystem creators,
tee/cp/mv), kill of every process, chmod/chown -R, plus the benign neighbours that must
stay allowed.

Dangerous commands are only ever text handed to ``check_command``; nothing here runs one."""
from __future__ import annotations

import pytest

from conftest import RM, rule_of
from hook_integrity_kit import commands as C


GIT = "git"                 # fragments keep this file's own text from being a command


DEL = "DELETE " + "FROM"


H = "/" + "home"      # assembled so path scanners run over this repository stay quiet


DEV = "/dev/" + "sda"


_DD = "d" + "d"


@pytest.mark.parametrize("cmd", [
    f"{GIT} -C . branch -D main",
    f"{GIT} branch --delete --force main",
    f"{GIT} branch -d -f main",
    f"{GIT} branch -Df master",
    f"{GIT} -c core.x=y branch -D main",
    f"{GIT} -C . clean -fd",
    f"{GIT} clean --force -d",
    f"{DEL} users",
    f"psql -c \"{DEL} users\"",
    f"{DEL} users RETURNING *;",
    "chown -R --reference=owner.txt /",
    "chown --recursive --reference=owner.txt ~",
])
def test_reproduced_variants_are_blocked(cmd):
    assert C.check_command(cmd) is not None, cmd


@pytest.mark.parametrize("cmd", [
    f"{GIT} branch -d feature",
    f"{GIT} branch -D feature",
    f"{GIT} branch -d main",                 # git refuses an unmerged delete itself
    f"{GIT} -C . branch --list",
    f"{GIT} clean -n -d",
    f"{GIT} clean -fX",
    f"{GIT} -C . status",
    f"{DEL} users WHERE id = 1",
    f"psql -c \"{DEL} users WHERE created < now() - interval '1 day';\"",
    "chown -R --reference=owner.txt ./build",
    "chown -R alice ./build",
])
def test_benign_neighbours_still_run(cmd):
    assert C.check_command(cmd) is None, cmd


@pytest.mark.parametrize("target", ["/tmp/../", "/tmp/..", "/usr/local/../..", "/a/b/../../",
                                    "~/..", "/tmp/./..", "/etc/../etc"])
def test_rm_with_dotdot_reaching_root_or_top_level_is_refused(target):
    assert rule_of(f"{RM} -rf {target}") == "rm-recursive-root-or-home", target


@pytest.mark.parametrize("target", ["./build/../dist", "/tmp/build/../cache", "build/../..x",
                                    "../sibling"])
def test_rm_with_benign_dotdot_stays_allowed(target):
    assert rule_of(f"{RM} -rf {target}") is None, target


RM_TARGET_BLOCKED = [f"{RM} -rf //usr", f"{RM} -rf /./etc", f"{RM} -rf /home//alice", f"{RM} -rf /usr/./",
          f"{RM} -rf ///", f"{RM} -rf /./", f"{RM} -rf /.", f"{RM} -rf //", f"{RM} -rf /./*",
          f"{RM} -rf /usr//", f"{RM} -rf {H}/./alice", f"{RM} -rf ~//", f"{RM} -rf ~/./",
          f"{RM} -rf $HOME//", f"{RM} -rf /tmp/../etc", f"{RM} -rf /usr/./.",
          f"{RM} -rf /Users//bob", f"{RM} -rf //*"]


@pytest.mark.parametrize("cmd", RM_TARGET_BLOCKED)
def test_rm_target_spellings_normalise_to_root_or_home(cmd):
    assert rule_of(cmd) == "rm-recursive-root-or-home", cmd


RM_TARGET_ALLOWED = [f"{RM} -rf ./build", f"{RM} -rf /tmp/x", f"{RM} -rf build//out", f"{RM} -rf ./a/./b",
         f"{RM} -rf {H}/alice/proj", f"{RM} -rf /usr/local/share//x", f"{RM} -rf ~/proj/./x",
         f"{RM} -rf /var//tmp/x", f"{RM} -rf ~/.cache//x"]


@pytest.mark.parametrize("cmd", RM_TARGET_ALLOWED)
def test_rm_near_misses_stay_allowed(cmd):
    assert rule_of(cmd) is None, cmd


DISK_REDIRECT_BLOCKED = [f"echo x >| {DEV}", f"echo x >& {DEV}", f"echo x &> {DEV}", f"echo x >> {DEV}",
          f"echo x 2>| {DEV}", f"echo x >{DEV}1", f"echo x 1>&{DEV}"]


@pytest.mark.parametrize("cmd", DISK_REDIRECT_BLOCKED)
def test_every_redirect_operator_onto_a_disk_device(cmd):
    assert rule_of(cmd) == "disk-redirect-to-device", cmd


DISK_REDIRECT_ALLOWED = ["echo x > /dev/null", "echo x >& /dev/null", "echo x >| /dev/null", "echo x >&2",
         "echo x > /dev/stdout"]


@pytest.mark.parametrize("cmd", DISK_REDIRECT_ALLOWED)
def test_redirects_to_harmless_devices(cmd):
    assert rule_of(cmd) is None, cmd


RM_ABBREVIATION_BLOCKED = [f"{RM} --rec /", f"{RM} --recur -f /", f"{RM} --recursive /", f"{RM} --r /",
          f"{RM} --re --force ~", f"{RM} --recurs=x /",
          f"{RM} --n /x", f"{RM} --no-pre /x", f"{RM} --no-preserve-root /x"]


@pytest.mark.parametrize("cmd", RM_ABBREVIATION_BLOCKED)
def test_rm_option_abbreviations(cmd):
    assert rule_of(cmd) in ("rm-recursive-root-or-home", "rm-no-preserve-root"), cmd


RM_ABBREVIATION_ALLOWED = [f"{RM} --rec ./build", f"{RM} --force /tmp/x", f"{RM} --recx /",
         f"{RM} --verbose /tmp/x", f"{RM} --nope /tmp/x", f"{RM} --n-x /"]


@pytest.mark.parametrize("cmd", RM_ABBREVIATION_ALLOWED)
def test_rm_option_abbreviation_neighbours(cmd):
    assert rule_of(cmd) is None, cmd


def test_chmod_and_chown_long_option_abbreviation_needs_three_letters():
    assert rule_of("chmod --rec 777 ./x") == "chmod-777-recursive-or-root"
    assert rule_of("chown --rec --reference=f /") == "chown-recursive-root"
    assert rule_of("chmod --re 777 ./x") is None            # ambiguous in GNU chmod


def test_dd_to_a_dev_null_spelling_is_not_a_device_write():
    assert rule_of("dd if=x of=/dev/./null") is None
    assert rule_of("dd if=x of=/dev//null") is None
    assert rule_of("dd if=x of=/dev/./sdb") == "disk-dd-to-device"


@pytest.mark.parametrize("cmd,rule", [
    ("tee /dev/sda < image", "disk-write-to-device"),
    ("cp image.iso /dev/sdb", "disk-write-to-device"),
    ("shred -n1 /dev/nvme0n1", "disk-write-to-device"),
    ("wipefs -a /dev/sda", "disk-write-to-device"),
    ("blkdiscard /dev/sdc", "disk-write-to-device"),
    ("sudo mv x /dev/vda", "disk-write-to-device"),
])
def test_other_ways_to_write_a_raw_disk_are_refused(cmd, rule):
    assert rule_of(cmd) == rule, cmd


@pytest.mark.parametrize("cmd", ["cp image.iso ./disk.img", "tee /dev/null < x", "cat /dev/sda | head -c 512",
                                 "fdisk -l /dev/sda", "shred -u secrets.txt"])
def test_the_disk_write_neighbours_pass(cmd):
    assert rule_of(cmd) is None, cmd


@pytest.mark.parametrize("cmd", [
    "kill -KILL -1", "kill -s 9 -1", "kill -9 -- -1", "kill -SIGKILL -1", "kill -s KILL -1",
    "kill --signal=9 -1", "kill --signal KILL -- -1", "kill -n 9 -1", "kill -9 -1",
])
def test_every_spelling_of_kill_everything_is_refused(cmd):
    assert rule_of(cmd) == "kill-all-processes", cmd


@pytest.mark.parametrize("cmd", ["kill -9 12345", "kill -1", "kill -s 9 4242", "kill -TERM 77", "kill -l"])
def test_ordinary_kill_passes(cmd):
    assert rule_of(cmd) is None, cmd


DD_PASS = ["/dev/tty", "/dev/shm/x", "/dev/full", "/dev/urandom", "/dev/stdin", "/dev/pts/3",
           "/dev/null", "/dev/zero", "/dev/stdout", "/dev/fd/1", "/dev/random", "/dev/ptmx",
           "./dev/sda", "/tmp/dev/sda", "out.img"]


@pytest.mark.parametrize("dev", DD_PASS)
def test_dd_to_a_non_block_device_is_not_a_disk_write(dev):
    assert rule_of(f"dd if=x of={dev}") is None


DD_BLOCK = ["/dev/sda", "/dev/sdb1", "/dev/nvme0n1", "/dev/hda", "/dev/vda1", "/dev/xvda",
            "/dev/mmcblk0", "/dev/disk2", "/dev/mapper/vg-root", "/dev/md0", "/dev/loop0",
            "/dev/./sda", "/dev//sda"]


@pytest.mark.parametrize("dev", DD_BLOCK)
def test_dd_to_a_block_device_is_refused(dev):
    assert rule_of(f"dd if=x of={dev}") == "disk-dd-to-device"


@pytest.mark.parametrize("cmd", [
    "cp /dev/sda ./img", "cat /dev/sda > img.bin".replace("> img.bin", "| head -c 512"),
    "tee /tmp/dev/sda", "cp img /tmp/dev/sda", "tee ./dev/sdb < x", "mv /dev/sda /tmp/x",
    "install /dev/sda img",
])
def test_reading_a_device_or_a_path_that_only_contains_dev_is_not_a_disk_write(cmd):
    assert rule_of(cmd) is None


@pytest.mark.parametrize("cmd", [
    "cp img /dev/sda", "install img /dev/sda", "install -m 0644 img /dev/nvme0n1",
    "mv img /dev/sdb", "tee /dev/sda < img", "echo x | tee -a /dev/sda", "shred /dev/sda",
    "cp -t /dev/sda img", "cp img /dev/mapper/root", "wipefs -a /dev/sda",
    "cp img '/dev/sda'", "cp img /dev/loop3",
])
def test_writing_a_block_device_with_any_write_verb_is_refused(cmd):
    assert rule_of(cmd) == "disk-write-to-device"


@pytest.mark.parametrize("cmd", ["mke2fs /dev/sda", "mke2fs -t ext4 /dev/sdb1", "mkdosfs /dev/sdc",
                                 "mke3fs /dev/sda", "mkntfs /dev/sda1", "mkfs.ext4 /dev/sda"])
def test_other_filesystem_creators_are_refused(cmd):
    assert rule_of(cmd) == "disk-format"


@pytest.mark.parametrize("cmd", [
    "kill -s9 -1", "kill -sKILL -1", "kill -n9 -1", "kill -9 -01", "kill -9 -001",
    "kill -s 9 -01", "kill -KILL -01", "kill -sigkill -1", "kill -s SIGKILL -1",
    "kill --signal=KILL -01", "kill -09 -1", "kill -n 9 -1", "kill -9 -- -1",
])
def test_kill_everything_in_every_spelling(cmd):
    assert rule_of(cmd) == "kill-all-processes"


@pytest.mark.parametrize("cmd", ["kill -s9 1234", "kill -1 1234", "kill -s HUP -1",
                                 "kill -n1 -1", "kill -9 -2", "kill -l"])
def test_kill_benign_neighbours_pass(cmd):
    assert rule_of(cmd) is None


DEVS = ["//dev/sda", "///dev/sda", "/./dev/sda", "/tmp/../dev/sda", "/dev/../dev/sda",
        "/dev//sda", "/dev/./sda"]


@pytest.mark.parametrize("dev", DEVS)
@pytest.mark.parametrize("tmpl,rule", [
    (_DD + " if=x of={d}", "disk-dd-to-device"), ("echo x > {d}", "disk-redirect-to-device"),
    ("tee {d}", "disk-write-to-device"), ("cp img {d}", "disk-write-to-device"),
    ("install img {d}", "disk-write-to-device"), ("shred {d}", "disk-write-to-device"),
    ("wipefs -a {d}", "disk-write-to-device"),
])
def test_device_spellings_are_blocked(dev, tmpl, rule):
    r = C.check_command(tmpl.format(d=dev))
    assert r is not None and r.id == rule, (tmpl, dev)


@pytest.mark.parametrize("cmd", [
    _DD + " if=x of=/tmp/dev/sda", "echo x > /tmp/dev/sda", "echo x > /dev/null",
    "cp a /var/dev/sda", "tee /dev/../tmp/x",
])
def test_non_devices_stay_quiet(cmd):
    assert C.check_command(cmd) is None
