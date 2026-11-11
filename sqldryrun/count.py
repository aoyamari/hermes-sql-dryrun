"""Ask the database how many rows a statement would touch — without changing anything.

* SQLite: opened in-process with ``mode=ro`` (the file cannot be written).
* Postgres: ``psql`` with ``default_transaction_read_only=on`` and a statement timeout.
* MySQL/MariaDB: the client inside ``START TRANSACTION READ ONLY ... ROLLBACK``.

The WHERE clause the agent wrote is reused verbatim inside ``SELECT COUNT(*)``,
so the count matches exactly what the DELETE/UPDATE would hit. Because the
session is read-only, a WHERE clause that calls a side-effecting function still
can't write.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from .extract import Target
from .parse import Finding


@dataclass
class Count:
    affected: Optional[int] = None
    total: Optional[int] = None
    error: str = ""


def _count_queries(f: Finding):
    table = f.table
    src = f"{table} AS {f.alias}" if f.alias else table
    total_q = f"SELECT COUNT(*) FROM {table}"
    if f.kind in ("DROP", "TRUNCATE", "ALTER_DROP") or not f.has_where:
        return total_q, None
    return total_q, f"SELECT COUNT(*) FROM {src} WHERE {f.where}"


def _sqlite(target: Target, total_q: str, where_q: Optional[str], timeout: float) -> Count:
    path = target.db_path
    if not os.path.isfile(path):
        return Count(error=f"database file not found: {path}")
    deadline = time.monotonic() + timeout
    uri = "file:" + path.replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=min(timeout, 2.0))
    except sqlite3.Error as exc:
        return Count(error=f"sqlite: {exc}")
    try:
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        total = conn.execute(total_q).fetchone()[0]
        affected = conn.execute(where_q).fetchone()[0] if where_q else total
        return Count(affected=int(affected), total=int(total))
    except sqlite3.Error as exc:
        msg = str(exc)
        if "interrupted" in msg:
            msg = f"count timed out after {timeout:g}s"
        return Count(error=f"sqlite: {msg}")
    finally:
        conn.close()


def _run(cmd, env, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout)


def _ints(stdout: str):
    vals = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.lstrip("-").isdigit():
            vals.append(int(line))
    return vals


def _postgres(target: Target, total_q: str, where_q: Optional[str], timeout: float) -> Count:
    env = dict(os.environ)
    ms = max(1, int(timeout * 1000))
    env["PGOPTIONS"] = (env.get("PGOPTIONS", "") +
                        f" -c default_transaction_read_only=on -c statement_timeout={ms}").strip()
    cmd = [target.client or "psql", *target.conn_args, "-X", "-w", "-q", "-A", "-t",
           "-v", "ON_ERROR_STOP=1", "-c", total_q]
    if where_q:
        cmd += ["-c", where_q]
    try:
        cp = _run(cmd, env, timeout + 2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Count(error=f"psql: {exc}")
    if cp.returncode != 0:
        return Count(error="psql: " + (cp.stderr.strip().splitlines() or ["failed"])[-1])
    vals = _ints(cp.stdout)
    if not vals:
        return Count(error="psql: no count returned")
    total = vals[0]
    affected = vals[1] if where_q and len(vals) > 1 else total
    return Count(affected=affected, total=total)


def _mysql(target: Target, total_q: str, where_q: Optional[str], timeout: float) -> Count:
    script = "START TRANSACTION READ ONLY; " + total_q + ";"
    if where_q:
        script += " " + where_q + ";"
    script += " ROLLBACK;"
    cmd = [target.client or "mysql", *target.conn_args, "-N", "-B", "-e", script]
    try:
        cp = _run(cmd, dict(os.environ), timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Count(error=f"{os.path.basename(target.client or 'mysql')}: {exc}")
    if cp.returncode != 0:
        return Count(error="mysql: " + (cp.stderr.strip().splitlines() or ["failed"])[-1])
    vals = _ints(cp.stdout)
    if not vals:
        return Count(error="mysql: no count returned")
    total = vals[0]
    affected = vals[1] if where_q and len(vals) > 1 else total
    return Count(affected=affected, total=total)


def count_rows(f: Finding, target: Optional[Target], timeout: float = 5.0) -> Count:
    if target is None:
        return Count(error="no database target found in the command")
    if f.complex or not f.table:
        return Count(error=f"not counted ({f.detail or 'complex statement'})")
    if f.kind == "DROP" and f.detail != "DROP TABLE":
        return Count(error="not counted (whole database/schema)")
    total_q, where_q = _count_queries(f)
    if target.engine == "sqlite":
        c = _sqlite(target, total_q, where_q, timeout)
    elif target.engine == "postgres":
        c = _postgres(target, total_q, where_q, timeout)
    elif target.engine == "mysql":
        c = _mysql(target, total_q, where_q, timeout)
    else:
        return Count(error=f"unsupported engine {target.engine}")
    if c.affected is not None and f.limit is not None:
        c.affected = min(c.affected, f.limit)
    return c
