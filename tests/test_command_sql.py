"""check-command: SQL statements. DELETE without WHERE (through escapes, comments and later
WHEREs), DROP SCHEMA, TRUNCATE (SQL versus coreutils), and statements kept whole across lines.

Dangerous commands are only ever text handed to ``check_command`` or to the hook as input."""
from __future__ import annotations

import pytest

from conftest import rule_of
from hook_integrity_kit import commands as C


DELETES = [
    'psql -c "DELETE FROM \\"Users\\""',
    'psql -c "delete from \\"public\\".\\"Users\\""',
    'psql -c "DELETE FROM \\"Users\\";"',
    'psql -c "Delete From \\"Mixed Case\\""',
    'psql -c "DELETE FROM \\"Users\\" ; SELECT 1"',
    'psql -c "DELETE FROM \\\\\\"Users\\\\\\""',
    'bash -c "psql -c \\"DELETE FROM \\\\\\"Users\\\\\\"\\""',
    'mysql -e "DELETE FROM \\`users\\`"',
    "psql -c 'DELETE FROM \"Users\"'",
    'psql -c "DELETE FROM \\"public\\".\\"Users\\" ; DELETE FROM \\"t\\" WHERE a=1; '
    'DELETE FROM \\"u\\""',
    "psql -c \"DELETE FROM \\\"Users\\\"\" --no-psqlrc",
    'psql -c "DELETE FROM public.\\"Users\\""',
]


@pytest.mark.parametrize("cmd", DELETES)
def test_delete_without_where_is_seen_through_shell_escapes(cmd):
    assert rule_of(cmd) == "sql-delete-without-where", cmd


DELETE_NEIGHBOURS = [
    'psql -c "DELETE FROM \\"Users\\" WHERE id = 1"',
    'psql -c "DELETE FROM \\"Users\\" WHERE \\"id\\" = 1"',
    'psql -c "delete from \\"public\\".\\"Users\\" where id=1"',
    'psql -c "DELETE FROM \\"Users\\" WHERE true"',
    "psql -c 'DELETE FROM \"Users\" WHERE id = 1'",
    'mysql -e "DELETE FROM \\`users\\` WHERE id = 1"',
    'psql -c "SELECT \\"deleted\\" FROM \\"Users\\""',
    'psql -c "DELETE FROM \\"a\\" WHERE x = 1; DELETE FROM \\"b\\" WHERE y = 2"',
]


@pytest.mark.parametrize("cmd", DELETE_NEIGHBOURS)
def test_delete_with_where_stays_allowed_through_shell_escapes(cmd):
    assert rule_of(cmd) is None, cmd


SQL_COMMENT_BLOCKED = [
    "psql -c \"DELETE/**/FROM users\"", "psql -c \"DELETE /* x */ FROM users\"",
    "psql -c \"DROP/**/TABLE users\"", "psql -c \"DROP /* c */ DATABASE d\"",
    "psql -c \"DELETE -- c\nFROM users\"", "psql -c \"DELETE FROM users /* WHERE id=1 */\"",
    "psql -c \"TRUNCATE/**/TABLE users\"", "mysql -e 'DELETE/**/FROM `t`'",
    "psql -c \"DELETE FROM users -- WHERE id = 1\"",
]


@pytest.mark.parametrize("cmd", SQL_COMMENT_BLOCKED)
def test_sql_comments_do_not_hide_statements(cmd):
    assert rule_of(cmd) is not None, cmd


SQL_COMMENT_ALLOWED = [
    "psql -c \"DELETE FROM users WHERE id = 1\"",
    "psql -c \"DELETE/**/FROM users/**/WHERE/**/id=1\"",
    "psql -c \"DROP TABLE IF EXISTS t\"", "psql -c \"DROP/**/TABLE/**/IF EXISTS t\"",
]


@pytest.mark.parametrize("cmd", SQL_COMMENT_ALLOWED)
def test_sql_comment_neighbours(cmd):
    assert rule_of(cmd) is None, cmd


COREUTILS_TRUNCATE_ALLOWED = ["truncate file -s 0", "truncate -s 0 file", "truncate log.txt -s 100M", "truncate foo -s0"]


@pytest.mark.parametrize("cmd", COREUTILS_TRUNCATE_ALLOWED)
def test_coreutils_truncate_is_not_sql(cmd):
    assert rule_of(cmd) is None, cmd


SQL_TRUNCATE_BLOCKED = ["psql -c 'TRUNCATE users'", "psql -c \"TRUNCATE TABLE users\"", "TRUNCATE TABLE users;",
          "mysql -e 'truncate orders;'", "echo \"TRUNCATE users, orders;\" | psql",
          "sqlite3 db 'TRUNCATE t'"]


@pytest.mark.parametrize("cmd", SQL_TRUNCATE_BLOCKED)
def test_sql_truncate_still_refused(cmd):
    assert rule_of(cmd) == "sql-truncate-table", cmd


@pytest.mark.parametrize("cmd", [
    'psql -c "DELETE FROM users" | grep -i where',
    'psql -c "DELETE FROM users" -U where',
    'psql -c "DELETE FROM users" -f where.sql',
    'psql -c "DELETE FROM users" -c "SELECT 1 WHERE 1"',
    'psql -c "DELETE FROM users" && echo where',
    'mysql -e "DELETE FROM users" -D where',
    'sqlite3 db "DELETE FROM users" "SELECT 1 WHERE 1"',
    "sqlite3 db 'DELETE FROM users' 'SELECT 1 WHERE 1'",
    'psql -c "DELETE FROM users"; echo where',
    "echo it's; psql -c \"DELETE FROM users\" | grep -i where",
    "echo \"it's\"; psql -c \"DELETE FROM users\" -c \"SELECT 1 WHERE 1\"",
    'bash -c "psql -c \\"DELETE FROM users\\" | grep where"',
    "bash -c 'psql -c \"DELETE FROM users\" | grep where'",
    "psql -c 'DELETE FROM users' --set=where=1",
])
def test_a_later_where_outside_the_statement_does_not_hide_a_delete(cmd):
    assert rule_of(cmd) == "sql-delete-without-where", cmd


@pytest.mark.parametrize("cmd", [
    'psql -c "DELETE FROM users WHERE id = 1" | grep -i where',
    'psql -c "DELETE FROM users WHERE id = 1" -c "SELECT 1"',
    'psql -c "DELETE FROM users\n  WHERE id = 1"',
    "psql <<EOF\nDELETE FROM users\nWHERE id = 1;\nEOF",
    'mysql -e "DELETE FROM users where id = 1" -D app',
    "sqlite3 db \"DELETE FROM users WHERE name = 'x'\"",
    'psql -c "DELETE FROM \\"Users\\" WHERE id = 1"',
    'bash -c "psql -c \\"DELETE FROM users WHERE id = 1\\" | cat"',
    'psql -c "DELETE FROM a WHERE x = 1; DELETE FROM b WHERE y = 2"',
])
def test_a_guarded_delete_stays_allowed(cmd):
    assert rule_of(cmd) is None, cmd


def test_sql_input_tools_keep_multi_line_statements_whole():
    ctx = C.Context(sql_input=True)
    assert rule_of("DELETE FROM users\nWHERE id = 1", ctx=ctx) is None
    assert rule_of("DELETE FROM users\n-- nothing here\n", ctx=ctx) == "sql-delete-without-where"


@pytest.mark.parametrize("cmd", [
    'psql -c "DROP SCHEMA public CASCADE"', "psql -c 'drop schema app cascade;'",
    'mysql -e "DROP SCHEMA x"', 'psql -c "DROP SCHEMA IF EXISTS public CASCADE"',
])
def test_drop_schema_is_refused(cmd):
    assert rule_of(cmd) == "sql-drop-schema"


@pytest.mark.parametrize("cmd", ['psql -c "CREATE SCHEMA x"', 'echo "drop schema is bad"',
                                 "psql -c 'SELECT 1'"])
def test_schema_benign_neighbours_pass(cmd):
    assert rule_of(cmd) is None
