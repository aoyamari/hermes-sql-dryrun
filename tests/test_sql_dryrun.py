import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_plugin():
    """Import the plugin as a package (so its relative imports work)."""
    name = "sql_dryrun_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "__init__.py",
                                                  submodule_search_locations=[str(ROOT)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


plugin = _load_plugin()
from sql_dryrun_under_test.sqldryrun.parse import analyze_sql, is_tautology, split_statements  # noqa: E402
from sql_dryrun_under_test.sqldryrun.extract import from_command, from_tool_call  # noqa: E402
from sql_dryrun_under_test.sqldryrun.policy import Settings, assess_all, directive  # noqa: E402


@pytest.fixture(autouse=True)
def _local_backend(monkeypatch):
    """Outside Hermes the backend is unknown (no counts); tests stub what config would say."""
    monkeypatch.setattr(plugin, "_backend", lambda: os.environ.get("TEST_BACKEND", "local"))
    monkeypatch.setattr(plugin, "_cwd", lambda: os.environ.get("TEST_CWD") or os.getcwd())


@pytest.fixture()
def shop(tmp_path, monkeypatch):
    db = tmp_path / "shop.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, active INT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, created_at TEXT, status TEXT);
    """)
    conn.executemany("INSERT INTO users VALUES (?,?,1)", [(i, f"u{i}@x.io") for i in range(1, 501)])
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?)",
                     [(i, i % 500 + 1, f"2025-{(i % 12) + 1:02d}-01", "paid" if i % 10 else "refunded")
                      for i in range(1, 12851)])
    conn.commit()
    conn.close()
    monkeypatch.setenv("TEST_CWD", str(tmp_path))
    return db


class FakeCtx:
    def __init__(self, settings=None):
        self.settings = settings or {}
        self.hooks, self.tools, self.commands = {}, {}, {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_hook(self, name, cb, **_):
        self.hooks[name] = cb

    def register_tool(self, name, toolset, schema, handler, **_):
        self.tools[name] = handler

    def register_command(self, name, handler, **_):
        self.commands[name] = handler


def hook(ctx, command):
    return ctx.hooks["pre_tool_call"](tool_name="terminal", args={"command": command}, task_id="t")


@pytest.fixture()
def ctx():
    c = FakeCtx()
    plugin.register(c)
    return c


# ── parsing ────────────────────────────────────────────────────────────────

def test_split_respects_quotes_and_comments():
    s = split_statements("DELETE FROM a WHERE x = 'a;b'; -- WHERE trap\nSELECT 1 /* ; */")
    assert s == ["DELETE FROM a WHERE x = 'a;b'", "SELECT 1"]


@pytest.mark.parametrize("where,expected", [
    ("1=1", True), ("1 = 1", True), ("true", True), ("id = id", True), ("'a'='a'", True),
    ("status='x' OR 1=1", True), ("(1=1)", True), ("id = 5", False), ("id > 0", False),
    ("status = 'a' AND 1=1", False), ("2 > 1", True),
])
def test_tautology(where, expected):
    assert is_tautology(where) is expected


def test_where_in_other_statement_does_not_count():
    f = analyze_sql("DELETE FROM users; SELECT * FROM logs WHERE id=1")
    assert len(f) == 1 and f[0].kind == "DELETE" and not f[0].has_where


def test_where_inside_string_is_not_a_where():
    f = analyze_sql("UPDATE notes SET body = 'see WHERE clause'")[0]
    assert f.kind == "UPDATE" and not f.has_where


def test_update_alias_and_limit():
    f = analyze_sql("UPDATE users u SET active = 0 WHERE u.id < 10 LIMIT 3")[0]
    assert (f.table, f.alias, f.where, f.limit) == ("users", "u", "u.id < 10", 3)


def test_update_from_join_is_complex():
    assert analyze_sql("UPDATE a SET x = b.x FROM b WHERE a.id = b.id")[0].complex


def test_drop_truncate_alter():
    kinds = [f.kind for f in analyze_sql(
        "DROP TABLE IF EXISTS old; TRUNCATE TABLE logs; ALTER TABLE users DROP COLUMN email; DROP INDEX i")]
    assert kinds == ["DROP", "TRUNCATE", "ALTER_DROP"]


# ── extraction ─────────────────────────────────────────────────────────────

def test_extract_clients(tmp_path):
    s = from_command("sqlite3 -header shop.db \"DELETE FROM orders\"", str(tmp_path))[0]
    assert s.target.engine == "sqlite" and s.target.db_path == str(tmp_path / "shop.db")
    s = from_command('PGPASSWORD=x psql -h db -U app shop -c "UPDATE users SET active=0"', "/")[0]
    assert s.target.engine == "postgres" and s.target.conn_args == ["--host=db", "--username=app", "shop"]
    assert s.target.env == {"PGPASSWORD": "x"} and not s.target.uncountable
    s = from_command("mysql -u root shop -e 'TRUNCATE logs'", "/")[0]
    assert s.target.engine == "mysql" and s.target.conn_args == ["--user=root", "--database=shop"]


def test_extract_heredoc_and_pipe(tmp_path):
    s = from_command("sqlite3 shop.db <<'SQL'\nDELETE FROM orders WHERE 1=1;\nSQL", str(tmp_path))[0]
    assert s.target and "DELETE FROM orders" in s.sql
    s = from_command('echo "UPDATE users SET active=0" | sqlite3 shop.db', str(tmp_path))[0]
    assert s.target and s.target.db_path.endswith("shop.db")


def test_extract_ignores_harmless():
    assert from_command("apt-get update && git status", "/") == []
    assert from_command("sqlite3 shop.db 'SELECT * FROM users'", "/") == []


def test_extract_execute_code_and_mcp():
    code = 'conn.execute("DELETE FROM users WHERE 1=1")'
    assert from_tool_call("execute_code", {"code": code}, "/")[0].sql == "DELETE FROM users WHERE 1=1"
    assert from_tool_call("mcp_postgres_query", {"sql": "DROP TABLE users"}, "/")


# ── hook end to end (real SQLite file) ─────────────────────────────────────

def test_safe_delete_passes(ctx, shop):
    assert hook(ctx, "sqlite3 shop.db \"DELETE FROM orders WHERE id = 7\"") is None


def test_where_one_equals_one_is_caught(ctx, shop):
    d = hook(ctx, "sqlite3 shop.db \"DELETE FROM users WHERE 1=1\"")
    assert d["action"] == "approve" and "always true" in d["message"] and "500" in d["message"]


def test_update_without_where_is_caught(ctx, shop):
    d = hook(ctx, "sqlite3 shop.db \"UPDATE users SET active=0\"")
    assert d["action"] == "approve" and "no WHERE" in d["message"]


def test_big_where_is_caught_with_count(ctx, shop):
    d = hook(ctx, "sqlite3 shop.db \"DELETE FROM orders WHERE created_at < '2025-12-01'\"")
    assert d["action"] == "approve" and "11,780 rows" in d["message"]


def test_where_matching_everything(ctx, shop):
    d = hook(ctx, "sqlite3 shop.db \"DELETE FROM orders WHERE created_at < '2030-01-01'\"")
    assert "ALL 12,850 rows" in d["message"]


def test_threshold_and_block_mode(shop):
    c = FakeCtx({"row_threshold": 2000, "mode": "block"})
    plugin.register(c)
    assert hook(c, "sqlite3 shop.db \"DELETE FROM orders WHERE status = 'refunded'\"") is None  # 1,285 rows
    d = hook(c, "sqlite3 shop.db \"DROP TABLE orders\"")
    assert d["action"] == "block" and "12,850 rows gone" in d["message"]


def test_count_is_read_only(ctx, shop):
    hook(ctx, "sqlite3 shop.db \"DELETE FROM users WHERE id IN (SELECT id FROM users)\"")
    conn = sqlite3.connect(shop)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 500


def test_unknown_table_does_not_crash(ctx, shop):
    d = hook(ctx, "sqlite3 shop.db \"DELETE FROM nope WHERE id = 1\"")
    assert d is None


def test_sql_impact_tool(ctx, shop):
    out = json.loads(ctx.tools["sql_impact"]({"sql": "UPDATE users SET active=0 WHERE id <= 40",
                                               "sqlite_db": "shop.db"}))
    st = out["statements"][0]
    assert st["rows_affected"] == 40 and st["rows_in_table"] == 500 and not st["flagged"]


def test_command_lists_recent(ctx, shop):
    hook(ctx, "sqlite3 shop.db \"UPDATE users SET active=0\"")
    assert "UPDATE users SET active=0" in ctx.commands["sql-dryrun"]("")


# ── review fixes (PR #153457) ─────────────────────────────────────────────

from sql_dryrun_under_test.sqldryrun.count import minimal_env, resolve_client  # noqa: E402
from sql_dryrun_under_test.sqldryrun.extract import Target  # noqa: E402


# 1. which binary runs
@pytest.mark.parametrize("cmd", [
    './psql shop -c "DELETE FROM users"',
    '/tmp/evil/psql shop -c "DELETE FROM users"',
    'bin/mysql shop -e "DELETE FROM users"',
])
def test_client_given_as_path_is_never_run(cmd, tmp_path):
    src = from_command(cmd, str(tmp_path))[0]
    path, why = resolve_client(src.target)
    assert path is None and "bare" in why


def test_client_on_path_inside_working_tree_is_refused(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "psql"
    fake.parent.mkdir()
    marker = tmp_path / "ran"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\necho on; echo 5; echo 5\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:/usr/bin:/bin")
    c = FakeCtx()
    plugin.register(c)
    monkeypatch.setenv("TEST_CWD", str(tmp_path))
    d = hook(c, 'psql shop -c "DELETE FROM users"')
    assert d["action"] == "approve" and "no WHERE" in d["message"]   # still flagged by shape
    assert not marker.exists()                                          # the planted binary never ran
    path, why = resolve_client(Target(engine="postgres", client="psql", tree=[str(tmp_path)]))
    assert path is None and "inside the working tree" in why


def test_sql_impact_tool_uses_same_client_rules(ctx, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    fake = tmp_path / "mysql"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    monkeypatch.setenv("TEST_CWD", str(tmp_path))
    out = json.loads(ctx.tools["sql_impact"]({"command": './mysql shop -e "DELETE FROM t WHERE id > 1"'}))
    assert "not counted" in out["statements"][0]["count_note"] and not marker.exists()


# 2. environment
def test_minimal_env_drops_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-secret")
    monkeypatch.setenv("PGHOST", "db")
    monkeypatch.setenv("PGOPTIONS", "-c default_transaction_read_only=off")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("MYSQL_PWD", "pw")
    pg = minimal_env(Target(engine="postgres", env={"PGPASSWORD": "x"}))
    assert pg["PGHOST"] == "db" and pg["PGPASSWORD"] == "x" and pg["LC_ALL"] == "C.UTF-8"
    assert "ANTHROPIC_API_KEY" not in pg and "OPENROUTER_API_KEY" not in pg
    assert "PGOPTIONS" not in pg and "MYSQL_PWD" not in pg
    my = minimal_env(Target(engine="mysql"))
    assert my["MYSQL_PWD"] == "pw" and "PGHOST" not in my and "ANTHROPIC_API_KEY" not in my


def test_env_prefix_pgoptions_is_not_taken():
    s = from_command('PGOPTIONS="-c default_transaction_read_only=off" psql shop -c "DELETE FROM t"', "/")[0]
    assert "PGOPTIONS" not in s.target.env


# 3. connection args can't break the read-only session
@pytest.mark.parametrize("cmd,reason", [
    ('mysql --init-command="SET autocommit=1" shop -e "DELETE FROM t"', "allowlist"),
    ('mysql --defaults-extra-file=x.cnf shop -e "DELETE FROM t"', "allowlist"),
    ('mysql --defaults-file=/etc/mysql/app.cnf shop -e "DELETE FROM t"', "allowlist"),
    ('mysql -p shop -e "DELETE FROM t"', "password"),
    ("psql \"host=db dbname=shop options='-c default_transaction_read_only=off'\" -c \"DELETE FROM t\"",
     "options="),
    ('psql "postgresql://db/shop?options=-c%20x" -c "DELETE FROM t"', "options="),
    ('psql -d "dbname=shop options=x" -c "DELETE FROM t"', "options="),
    ('psql --set=FOO=1 --pset=x -o out.txt -W shop -c "DELETE FROM t"', "allowlist"),
    ('psql "$OTHER_VAR" -c "DELETE FROM t"', "OTHER_VAR"),
])
def test_unsafe_connection_args_skip_the_count(cmd, reason):
    t = from_command(cmd, "/")[0].target
    assert t.uncountable and reason in t.uncountable


def test_allowed_connection_args():
    t = from_command('mysql -hdb -P3306 -uroot -psecret --socket=/run/m.sock shop -e "DELETE FROM t"', "/")[0].target
    assert not t.uncountable
    assert t.conn_args == ["--password=secret", "--host=db", "--port=3306", "--user=root",
                           "--socket=/run/m.sock", "--database=shop"]
    t = from_command('psql -qAt -h db -p 5432 -U app -d shop -c "DELETE FROM t"', "/")[0].target
    assert not t.uncountable and t.conn_args == ["--host=db", "--port=5432", "--username=app", "--dbname=shop"]


def test_database_url_is_expanded(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://app@db/shop")
    t = from_command('psql "$DATABASE_URL" -c "DELETE FROM t"', "/")[0].target
    assert not t.uncountable and t.conn_args == ["postgresql://app@db/shop"]
    monkeypatch.setenv("DATABASE_URL", "postgresql://db/shop?options=-c%20x")
    assert "options=" in from_command('psql "$DATABASE_URL" -c "DELETE FROM t"', "/")[0].target.uncountable


# 4. only count on the local backend
@pytest.mark.parametrize("backend", ["docker", "ssh", "modal", "daytona", "unknown"])
def test_non_local_backend_flags_by_shape_only(shop, monkeypatch, backend):
    monkeypatch.setenv("TEST_BACKEND", backend)
    c = FakeCtx()
    plugin.register(c)
    d = hook(c, "sqlite3 shop.db \"UPDATE users SET active=0\"")
    assert d["action"] == "approve" and "no WHERE" in d["message"] and "500" not in d["message"]
    assert hook(c, "sqlite3 shop.db \"DELETE FROM orders WHERE created_at < '2030-01-01'\"") is None
    out = json.loads(c.tools["sql_impact"]({"sql": "DELETE FROM users WHERE id < 9", "sqlite_db": "shop.db"}))
    assert backend in out["statements"][0]["count_note"]


# ── second review round ───────────────────────────────────────────────────

from sql_dryrun_under_test.sqldryrun import count as count_mod  # noqa: E402
from sql_dryrun_under_test.sqldryrun.policy import Settings as _S, assess as _assess  # noqa: E402


def _never_run(*a, **k):
    raise AssertionError("a database client was launched")


@pytest.mark.parametrize("sql", [
    "DELETE FROM t WHERE a = 'x\\' ; COMMIT; DELETE FROM users; --'",   # reviewer's case
    "DELETE FROM t WHERE a = 'x;y'",
    "UPDATE t SET b = 1 WHERE a = E'\\x41'",
    "DELETE FROM t WHERE a LIKE 'c:\\temp%'",
])
@pytest.mark.parametrize("client", ["psql shop -c", "mysql shop -e", "sqlite3 shop.db"])
def test_semicolon_or_backslash_is_never_counted(sql, client, shop, monkeypatch):
    monkeypatch.setattr(count_mod, "_run", _never_run)
    monkeypatch.setattr(count_mod, "_sqlite", _never_run)
    src = from_command(f'{client} "{sql}"', str(shop.parent))
    assert src, "statement should still be seen"
    for a in [x for s_ in src for x in _assess(s_, _S())]:
        assert a.count.affected is None
        if a.finding.kind in ("DELETE", "UPDATE") and a.finding.has_where:
            assert "not counted" in a.count.error or "no database" in a.count.error
            assert a.flagged                                  # shape-flagged instead


def test_escape_case_through_hook_asks_and_runs_nothing(ctx, shop, monkeypatch):
    monkeypatch.setattr(count_mod, "_run", _never_run)
    monkeypatch.setenv("TEST_CWD", str(shop.parent))
    d = hook(ctx, "psql shop -c \"DELETE FROM t WHERE a = 'x\\' ; COMMIT; DELETE FROM users; --'\"")
    assert d["action"] == "approve" and "backslash" in d["message"]


def test_mysql_count_uses_no_defaults(monkeypatch):
    seen = {}

    def fake_run(cmd, env, timeout):
        seen["cmd"] = cmd
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, "10\n3\n", "")
    monkeypatch.setattr(count_mod, "_run", fake_run)
    monkeypatch.setattr(count_mod, "resolve_client", lambda t: ("/usr/bin/mysql", ""))
    src = from_command('mysql -uroot shop -e "DELETE FROM t WHERE id < 4"', "/")[0]
    a = _assess(src, _S())[0]
    assert a.count.affected == 3 and seen["cmd"][1] == "--no-defaults"
    assert not any(x.startswith("--defaults-file") for x in seen["cmd"])


def test_no_private_hermes_imports():
    src = (ROOT / "__init__.py").read_text()
    assert "terminal_tool" not in src and "_task_env_overrides" not in src and "_qualify_task_key" not in src


def test_backend_unknown_outside_hermes(monkeypatch):
    monkeypatch.undo()                       # drop the autouse stub
    monkeypatch.setitem(sys.modules, "hermes_cli.config", None)
    assert plugin._backend() == "unknown"


# ── self-audit: the WHERE runs before approval, so it must be a plain predicate ──

from sql_dryrun_under_test.sqldryrun.parse import where_uncountable  # noqa: E402


@pytest.mark.parametrize("where", [
    "id = 7", "created_at < '2025-12-01'", "status IN ('a', 'b') AND total >= 10.5",
    "id IN (SELECT user_id FROM orders WHERE status = 'refunded')",
    "lower(email) LIKE '%@x.io' OR coalesce(active, 0) = 0",
    "created_at < now() - interval '30 days'", "created_at < NOW() - INTERVAL 30 DAY",
    "created_at < date('now', '-30 day')", "name = 'it''s (fine) INTO here'",
    "EXISTS (SELECT 1 FROM users u WHERE u.id = orders.user_id)", 'u."Email" IS NULL',
    "CAST(total AS numeric(10,2)) > 5", "id BETWEEN 1 AND 9", "name = \"O'Brien\"",
])
def test_plain_predicates_are_countable(where):
    assert where_uncountable(where) == ""


@pytest.mark.parametrize("where,why", [
    ("1 INTO OUTFILE '/tmp/x'", "INTO"),
    ("1 INTO DUMPFILE '/tmp/x'", "INTO"),
    ("pg_reload_conf()", "pg_reload_conf"),
    ("pg_terminate_backend(pid) AND true", "pg_terminate_backend"),
    ("id = 1 AND set_config('application_name', 'x', false) IS NOT NULL", "set_config"),
    ("id IN (SELECT a FROM dblink('host=evil', 'DELETE FROM t') AS r(a int))", "dblink"),
    ("id IN (SELECT lo_export(1, '/tmp/x'))", "lo_export"),
    ("pg_catalog.pg_sleep(60) IS NULL", "schema-qualified"),
    ('"pg_reload_conf"()', "quoted function"),
    ("`sys_exec`('id')", "quoted function"),
    ("sleep(60)", "sleep"), ("load_file('/etc/passwd') IS NOT NULL", "LOAD_FILE"),
    ("a = $$ ' $$ OR pg_reload_conf() --'", "$"),
    ("a = 1 /*! INTO OUTFILE '/tmp/x' */", "comment"),
    ("a = 'unterminated", "unterminated"),
    ("id = 1 FOR UPDATE", "FOR UPDATE"),
    ("a = \"x ' y\" OR pg_reload_conf() IS NOT NULL OR b = 'z'", "pg_reload_conf"),
])
def test_side_effecting_where_is_refused(where, why):
    assert why.lower() in where_uncountable(where).lower()


@pytest.mark.parametrize("client", ["psql shop -c", "mysql shop -e", "sqlite3 shop.db"])
def test_side_effecting_where_never_reaches_a_database(client, shop, monkeypatch):
    monkeypatch.setattr(count_mod, "_run", _never_run)
    monkeypatch.setattr(count_mod, "_sqlite", _never_run)
    for sql in ("DELETE FROM users WHERE pg_reload_conf()",
                "DELETE FROM users WHERE 1 INTO OUTFILE '/tmp/x'"):
        src = from_command(f'{client} "{sql}"', str(shop.parent))[0]
        a = _assess(src, _S())[0]
        assert a.count.affected is None and "not counted" in a.count.error


@pytest.mark.parametrize("uri", [
    "postgresql://db/shop?%6Fptions=-c%20x", "postgresql://db/shop?a=1&OPTIONS=-c%20x",
    "postgresql://db/shop?%256Fptions=x", "host=db%20options=x",
])
def test_encoded_options_key_skips_the_count(uri):
    assert "options=" in from_command(f'psql "{uri}" -c "DELETE FROM t"', "/")[0].target.uncountable
