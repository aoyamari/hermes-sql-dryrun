import importlib.util
import json
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
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
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
    assert s.target.engine == "postgres" and s.target.conn_args == ["-h", "db", "-U", "app", "shop"]
    s = from_command("mysql -u root shop -e 'TRUNCATE logs'", "/")[0]
    assert s.target.engine == "mysql" and s.target.conn_args == ["-u", "root", "shop"]


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
