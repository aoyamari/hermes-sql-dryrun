"""sql-dryrun — see how many rows a destructive SQL statement touches before it runs.

Hermes' built-in approval only matches the *shape* of a command (``DELETE FROM``
with no ``WHERE`` on the same line, ``DROP TABLE``, ``TRUNCATE``). It lets
``UPDATE users SET active=0`` through, and ``DELETE FROM users WHERE 1=1``, and a
``DELETE ... WHERE`` that matches a million rows.

This plugin checks the *impact*: on every ``terminal`` / ``execute_code`` call,
and any tool that passes SQL in a ``sql``/``query`` argument, it finds the
DELETE/UPDATE/DROP/TRUNCATE statements, asks the database (read-only) how many
rows they hit, and escalates to Hermes' approval prompt with the number.

Registers:
- ``pre_tool_call`` hook — the guard
- ``sql_impact`` tool — lets the agent check a statement before running it
- ``/sql-dryrun`` command — settings and the last few checks
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from typing import Any, Deque, Dict

logger = logging.getLogger("sql-dryrun")

_RECENT: Deque[Dict[str, Any]] = deque(maxlen=20)
_GUARDED = ("terminal", "execute_code")


def _settings(ctx):
    from .sqldryrun.policy import Settings

    def get(key, default):
        try:
            v = ctx.get_config(key, default)
        except Exception:
            return default
        return default if v is None else v

    return Settings.from_getter(get)


def _terminal_setting(name: str, default: str) -> str:
    """Scope-aware TERMINAL_* read (per-profile under gateway multiplexing)."""
    try:
        from tools.terminal_scope import terminal_env
        return terminal_env(name, default) or default
    except Exception:
        return os.environ.get(name, default) or default


def _backend(task_id: str = "") -> str:
    """Terminal backend for this call. Counts only run when it is ``local``."""
    if task_id:
        try:
            from tools.terminal_tool import _qualify_task_key, _task_env_overrides
            env_type = (_task_env_overrides.get(_qualify_task_key(task_id)) or {}).get("env_type")
            if env_type:
                return str(env_type).strip().lower()
        except Exception:
            pass
    return _terminal_setting("TERMINAL_ENV", "local").strip().lower()


def _cwd() -> str:
    v = _terminal_setting("TERMINAL_CWD", "")
    if v and os.path.isdir(os.path.expanduser(v)):
        return os.path.abspath(os.path.expanduser(v))
    try:
        return os.getcwd()
    except OSError:
        return os.path.expanduser("~")


def _on_pre_tool_call(ctx, tool_name: str = "", args: Any = None, task_id: str = "", **_kw):
    from .sqldryrun.extract import from_tool_call
    from .sqldryrun.policy import assess_all, directive

    if not isinstance(args, dict):
        return None
    sources = from_tool_call(tool_name, args, _cwd(), backend=_backend(task_id))
    if not sources:
        return None
    settings = _settings(ctx)
    assessments = assess_all(sources, settings)
    result = directive(assessments, settings)
    for a in assessments:
        _RECENT.append({"at": time.strftime("%H:%M:%S"), "tool": tool_name,
                        "decision": (result or {}).get("action", "allow") if a.flagged else "allow",
                        **a.to_dict()})
    return result


def _handle_sql_impact(ctx, sql: str = "", command: str = "", sqlite_db: str = "",
                       workdir: str = "", task_id: str = "", **_kw) -> str:
    from .sqldryrun.extract import SqlSource, Target, from_command, restrict_to_backend, _resolve
    from .sqldryrun.policy import assess_all

    cwd = _cwd()
    base = _resolve(workdir, cwd) if workdir else cwd
    if command:
        sources = from_command(command, base)
    elif sql:
        target = Target(engine="sqlite", db_path=_resolve(sqlite_db, base)) if sqlite_db else None
        sources = [SqlSource(sql=sql, target=target,
                             origin=f"sqlite3 {sqlite_db}" if sqlite_db else "sql")]
    else:
        return json.dumps({"error": "pass `sql` (optionally with `sqlite_db`) or a full shell `command`"})
    # Same rules as the hook: working-tree clients refused, host counts only on a local backend.
    for s in sources:
        if s.target:
            s.target.tree = list({*s.target.tree, base, cwd})
    restrict_to_backend(sources, _backend(task_id))
    settings = _settings(ctx)
    results = [a.to_dict() for a in assess_all(sources, settings)]
    if not results:
        return json.dumps({"statements": [], "note": "no DELETE/UPDATE/DROP/TRUNCATE/ALTER DROP found"})
    return json.dumps({"row_threshold": settings.row_threshold, "statements": results}, ensure_ascii=False)


def _handle_command(ctx, raw: str = "") -> str:
    s = _settings(ctx)
    lines = [f"sql-dryrun — mode: {s.mode}, row threshold: {s.row_threshold:,}, "
             f"count timeout: {s.count_timeout_seconds:g}s, flag uncounted: {s.flag_uncounted}"]
    if not _RECENT:
        lines.append("No SQL checked yet this session.")
    else:
        lines.append("Recent checks (newest last):")
        for r in list(_RECENT)[-10:]:
            impact = "" if r["rows_affected"] is None else f" → {r['rows_affected']:,} rows"
            stmt = r["statement"] if len(r["statement"]) <= 70 else r["statement"][:69] + "…"
            lines.append(f"  {r['at']} [{r['decision']}] {stmt}{impact}")
    lines.append("Settings: plugins.entries.sql-dryrun.settings.{row_threshold,mode,count_timeout_seconds,flag_uncounted}")
    return "\n".join(lines)


def register(ctx):
    ctx.register_hook("pre_tool_call", lambda **kw: _on_pre_tool_call(ctx, **kw))
    ctx.register_tool(
        name="sql_impact",
        toolset="sql-dryrun",
        schema={
            "name": "sql_impact",
            "description": (
                "Dry-run a destructive SQL statement: reports how many rows a DELETE/UPDATE would touch "
                "(and table size for DROP/TRUNCATE) using a read-only count, without changing data. Use it "
                "before running DELETE/UPDATE on real data. Pass `sql` with `sqlite_db` for SQLite, or the "
                "full shell `command` (sqlite3/psql/mysql) you intend to run."),
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL to check"},
                    "sqlite_db": {"type": "string", "description": "Path to a SQLite database file"},
                    "command": {"type": "string",
                                "description": "Full shell command, e.g. psql \"$DATABASE_URL\" -c \"DELETE ...\""},
                    "workdir": {"type": "string", "description": "Directory relative paths resolve from"},
                },
            },
        },
        handler=lambda args, **kw: _handle_sql_impact(ctx, task_id=str(kw.get("task_id") or ""),
                                                       **{k: v for k, v in (args or {}).items() if k != "task_id"}),
        description="Read-only row-impact check for DELETE/UPDATE/DROP/TRUNCATE",
        emoji="🧮",
    )
    ctx.register_command(
        name="sql-dryrun",
        handler=lambda raw="", **kw: _handle_command(ctx, raw),
        description="Show sql-dryrun settings and the last SQL checks",
    )
    logger.info("sql-dryrun registered")
