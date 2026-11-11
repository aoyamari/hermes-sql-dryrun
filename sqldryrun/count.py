"""Ask the database how many rows a statement would touch — without changing anything.

* SQLite: opened in-process with ``mode=ro`` and ``trusted_schema=OFF``.
* Postgres: the system ``psql`` inside ``BEGIN TRANSACTION READ ONLY``; the
  session's ``transaction_read_only`` is checked with ``SHOW`` before any count
  runs, and the result is discarded if it isn't ``on``.
* MySQL/MariaDB: the system ``mysql``/``mariadb`` inside
  ``START TRANSACTION READ ONLY ... ROLLBACK``, with allowlisted connection flags only.

Which binary runs: only a bare ``psql`` / ``mysql`` / ``mariadb`` token, resolved
with ``shutil.which()`` and refused if it resolves inside the agent's working
tree. Anything else (``./psql``, ``/tmp/x/psql``, a file the model wrote) means
no count — the statement is still flagged by shape.

Which environment it gets: PATH, HOME, LANG, LC_*, TZ, plus libpq ``PG*``
variables (never ``PGOPTIONS``) or ``MYSQL_PWD``/``MYSQL_HOST``/``MYSQL_TCP_PORT``/
``MYSQL_UNIX_PORT``. Provider API keys and everything else stay out.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .extract import Target, allowed_env_key
from .parse import Finding

_CLIENT_NAMES = {"postgres": {"psql"}, "mysql": {"mysql", "mariadb"}}
_BASE_ENV = ("PATH", "HOME", "LANG", "TZ")


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


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_client(target: Target) -> Tuple[Optional[str], str]:
    """System client for the count, or (None, reason)."""
    tok = target.client
    allowed = _CLIENT_NAMES.get(target.engine, set())
    if tok not in allowed:
        return None, f"client {tok!r} isn't a bare {'/'.join(sorted(allowed))}"
    found = shutil.which(tok)
    if not found:
        return None, f"{tok} not found on PATH"
    real = os.path.realpath(found)
    trees = {os.path.realpath(d) for d in target.tree if d}
    try:
        trees.add(os.path.realpath(os.getcwd()))
    except OSError:
        pass
    for d in trees:
        if d in ("/", "") or not os.path.isdir(d):
            continue
        if _inside(real, d) or _inside(os.path.abspath(found), d):
            return None, f"{tok} resolves inside the working tree ({found})"
    # Run the PATH entry, not its realpath: Debian's psql/mysql are pg_wrapper-style
    # dispatchers that pick the real binary from the name they were called by.
    return os.path.abspath(found), ""


def minimal_env(target: Target) -> Dict[str, str]:
    env = {k: os.environ[k] for k in _BASE_ENV if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("LC_")})
    for source in (os.environ, target.env):
        env.update({k: v for k, v in source.items() if allowed_env_key(target.engine, k)})
    return env


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
        conn.execute("PRAGMA trusted_schema=OFF")
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


def _lines(stdout: str):
    return [ln.strip() for ln in stdout.splitlines() if ln.strip()]


def _ints(lines):
    return [int(x) for x in lines if x.lstrip("-").isdigit()]


def _postgres(target: Target, client: str, total_q: str, where_q: Optional[str], timeout: float) -> Count:
    env = minimal_env(target)
    ms = max(1, int(timeout * 1000))
    env["PGOPTIONS"] = f"-c default_transaction_read_only=on -c statement_timeout={ms}"
    cmd = [client, "--no-psqlrc", "--no-password", "--quiet", "--no-align", "--tuples-only",
           "--set=ON_ERROR_STOP=1",
           "--command=BEGIN TRANSACTION READ ONLY",
           "--command=SHOW transaction_read_only",
           f"--command={total_q}"]
    if where_q:
        cmd.append(f"--command={where_q}")
    cmd += ["--command=ROLLBACK", *target.conn_args]
    try:
        cp = _run(cmd, env, timeout + 2)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Count(error=f"psql: {exc}")
    if cp.returncode != 0:
        return Count(error="psql: " + (cp.stderr.strip().splitlines() or ["failed"])[-1])
    lines = _lines(cp.stdout)
    if not lines or lines[0] != "on":
        return Count(error="psql: couldn't confirm a read-only session, count discarded")
    vals = _ints(lines[1:])
    if not vals:
        return Count(error="psql: no count returned")
    total = vals[0]
    affected = vals[1] if where_q and len(vals) > 1 else total
    return Count(affected=affected, total=total)


def _mysql(target: Target, client: str, total_q: str, where_q: Optional[str], timeout: float) -> Count:
    script = "START TRANSACTION READ ONLY; " + total_q + ";"
    if where_q:
        script += " " + where_q + ";"
    script += " ROLLBACK;"
    conn = list(target.conn_args)
    head = [conn.pop(0)] if conn and conn[0].startswith("--defaults-file=") else []
    cmd = [client, *head, *conn, "--batch", "--skip-column-names", f"--execute={script}"]
    try:
        cp = _run(cmd, minimal_env(target), timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Count(error=f"{os.path.basename(client)}: {exc}")
    if cp.returncode != 0:
        return Count(error="mysql: " + (cp.stderr.strip().splitlines() or ["failed"])[-1])
    vals = _ints(_lines(cp.stdout))
    if not vals:
        return Count(error="mysql: no count returned")
    total = vals[0]
    affected = vals[1] if where_q and len(vals) > 1 else total
    return Count(affected=affected, total=total)


def count_rows(f: Finding, target: Optional[Target], timeout: float = 5.0) -> Count:
    if target is None:
        return Count(error="no database target found in the command")
    if target.uncountable:
        return Count(error=f"not counted: {target.uncountable}")
    if f.complex or not f.table:
        return Count(error=f"not counted ({f.detail or 'complex statement'})")
    if f.kind == "DROP" and f.detail != "DROP TABLE":
        return Count(error="not counted (whole database/schema)")
    total_q, where_q = _count_queries(f)
    if target.engine == "sqlite":
        c = _sqlite(target, total_q, where_q, timeout)
    elif target.engine in ("postgres", "mysql"):
        client, why = resolve_client(target)
        if client is None:
            return Count(error=f"not counted: {why}")
        if target.engine == "mysql":
            df = next((a.split("=", 1)[1] for a in target.conn_args if a.startswith("--defaults-file=")), None)
            if df and any(_inside(os.path.realpath(df), os.path.realpath(d)) for d in target.tree if d):
                return Count(error="not counted: --defaults-file is inside the working tree")
        runner = _postgres if target.engine == "postgres" else _mysql
        c = runner(target, client, total_q, where_q, timeout)
    else:
        return Count(error=f"unsupported engine {target.engine}")
    if c.affected is not None and f.limit is not None:
        c.affected = min(c.affected, f.limit)
    return c
