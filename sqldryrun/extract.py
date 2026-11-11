"""Find SQL in tool calls and, when possible, the database it will run against.

Recognised clients (anywhere in a shell pipeline):
  sqlite3 [opts] DB "SQL"          (also -cmd "SQL")
  psql [conn opts] -c "SQL"         (also --command=, postgres:// URIs)
  mysql / mariadb [conn opts] -e "SQL"

Everything else (heredocs, pipes into a client, python -c, execute_code, MCP
database tools) still gets its SQL analysed on shape, just without a target
database to count rows in.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .parse import looks_destructive

SQL_ARG_NAMES = ("sql", "query", "statement", "statements", "sql_query", "command_sql")


@dataclass
class Target:
    engine: str                     # sqlite | postgres | mysql
    client: str = ""                # executable as written (psql, mysql, mariadb, /usr/bin/psql)
    db_path: str = ""               # sqlite only, resolved absolute path
    conn_args: List[str] = field(default_factory=list)   # psql/mysql connection flags, minus the SQL


@dataclass
class SqlSource:
    sql: str
    target: Optional[Target] = None
    origin: str = ""                # human label: "sqlite3 shop.db", "psql", "execute_code", ...


_SEPARATORS = {"|", "||", "&&", ";", "&", "(", ")"}


def _tokens(command: str) -> Optional[List[str]]:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars="|&;()")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _segments(tokens: List[str]) -> List[List[str]]:
    segs, cur = [], []
    for t in tokens:
        if t in _SEPARATORS or (t and set(t) <= set("|&;()")):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _strip_env_prefix(seg: List[str]) -> List[str]:
    i = 0
    while i < len(seg) and re.match(r"^[A-Za-z_]\w*=", seg[i]):
        i += 1
    while i < len(seg) and seg[i] in ("sudo", "env", "time", "nice", "command", "exec"):
        i += 1
        while i < len(seg) and (seg[i].startswith("-") or re.match(r"^[A-Za-z_]\w*=", seg[i])):
            i += 1
    return seg[i:]


def _resolve(path: str, cwd: str) -> str:
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


_SQLITE_VALUE_OPTS = {"-cmd", "-separator", "-nullvalue", "-newline", "-init", "-vfs",
                      "-maxsize", "-mmap", "-pagecache", "-lookaside", "-heap", "-escape"}


def _parse_sqlite(args: List[str], client: str, cwd: str) -> Optional[SqlSource]:
    cmds, positional, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-cmd", "--cmd") and i + 1 < len(args):
            cmds.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-") and a.lstrip("-") and ("-" + a.lstrip("-")) in _SQLITE_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            i += 1
            continue
        positional.append(a)
        i += 1
    if not positional:
        return None
    db = positional[0]
    sql = "; ".join(cmds + positional[1:])
    if not sql.strip():
        return None
    target = None
    if db not in (":memory:", ""):
        target = Target(engine="sqlite", client=client, db_path=_resolve(db, cwd))
    return SqlSource(sql=sql, target=target, origin=f"sqlite3 {db}")


def _parse_psql(args: List[str], client: str) -> Optional[SqlSource]:
    sqls, conn, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "--command") and i + 1 < len(args):
            sqls.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--command="):
            sqls.append(a.split("=", 1)[1])
            i += 1
            continue
        if a.startswith("-c") and len(a) > 2 and not a.startswith("--"):
            sqls.append(a[2:])
            i += 1
            continue
        if a in ("-f", "--file", "-o", "--output", "-L", "--log-file") and i + 1 < len(args):
            i += 2
            continue
        if a in ("-1", "--single-transaction", "-a", "-e", "-E", "-q", "-x", "-H", "-t", "-A",
                 "-n", "--echo-all", "--echo-queries", "--quiet"):
            i += 1
            continue
        if a in ("-v", "--set", "--variable", "-P", "--pset", "-F", "-R") and i + 1 < len(args):
            i += 2
            continue
        conn.append(a)
        i += 1
    if not sqls:
        return None
    return SqlSource(sql="; ".join(sqls), target=Target(engine="postgres", client=client, conn_args=conn),
                     origin="psql")


def _parse_mysql(args: List[str], client: str) -> Optional[SqlSource]:
    sqls, conn, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--execute") and i + 1 < len(args):
            sqls.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--execute="):
            sqls.append(a.split("=", 1)[1])
            i += 1
            continue
        if a.startswith("-e") and len(a) > 2 and not a.startswith("--"):
            sqls.append(a[2:])
            i += 1
            continue
        if a in ("-N", "-B", "-s", "-t", "-v", "--batch", "--silent", "--skip-column-names",
                 "--table", "--verbose", "--force", "-f"):
            i += 1
            continue
        conn.append(a)
        i += 1
    if not sqls:
        return None
    return SqlSource(sql="; ".join(sqls), target=Target(engine="mysql", client=client, conn_args=conn),
                     origin=os.path.basename(client))


_CLIENTS = ("sqlite3", "sqlite", "psql", "mysql", "mariadb")


def _client_source(exe_token: str, args: List[str], cwd: str, piped_sql: Optional[str] = None
                   ) -> Optional[SqlSource]:
    exe = os.path.basename(exe_token)
    if piped_sql is not None:
        if exe in ("sqlite3", "sqlite"):
            args = args + [piped_sql]
        elif exe == "psql":
            args = args + ["-c", piped_sql]
        elif exe in ("mysql", "mariadb"):
            args = args + ["-e", piped_sql]
    if exe in ("sqlite3", "sqlite"):
        return _parse_sqlite(args, exe_token, cwd)
    if exe == "psql":
        return _parse_psql(args, exe_token)
    if exe in ("mysql", "mariadb"):
        return _parse_mysql(args, exe_token)
    return None


_HEREDOC_CLIENT = re.compile(
    r"(?P<pre>(?:^|[\n;&|(])\s*(?:[A-Za-z_]\w*=\S+\s+)*)(?P<exe>\S*(?:sqlite3?|psql|mysql|mariadb))\b"
    r"(?P<args>[^\n|;&]*?)<<-?\s*['\"]?(?P<tag>\w+)['\"]?[^\n]*\n(?P<body>.*?)\n\s*(?P=tag)\b", re.S)


def from_command(command: str, cwd: str) -> List[SqlSource]:
    """SQL sources inside a shell command string."""
    found: List[SqlSource] = []

    # 1. Heredocs fed to a client: sqlite3 shop.db <<'SQL' ... SQL
    for m in _HEREDOC_CLIENT.finditer(command):
        args = _tokens(re.sub(r"[<>]\s*\S+", "", m.group("args"))) or []
        src = _client_source(m.group("exe"), args, cwd, piped_sql=m.group("body"))
        if src and looks_destructive(src.sql):
            found.append(src)
    if found:
        return found

    # 2. Inline SQL (-c / -e / positional), or `echo "SQL" | client`.
    tokens = _tokens(command)
    if tokens:
        segs = _segments(tokens)
        for idx, seg in enumerate(segs):
            seg = _strip_env_prefix(seg)
            if not seg or os.path.basename(seg[0]) not in _CLIENTS:
                continue
            src = _client_source(seg[0], seg[1:], cwd)
            if src is None and idx > 0:
                prev = _strip_env_prefix(segs[idx - 1])
                if prev and os.path.basename(prev[0]) in ("echo", "printf", "cat"):
                    body = " ".join(a for a in prev[1:] if not a.startswith("-"))
                    if looks_destructive(body):
                        src = _client_source(seg[0], seg[1:], cwd, piped_sql=body)
            if src and looks_destructive(src.sql):
                found.append(src)
    if found:
        return found
    # Fallback: SQL that reaches a client another way (heredoc, pipe, python -c ...).
    return from_text(command, origin="terminal")


_STRING_LIT = re.compile(
    r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', re.S)
_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\s*\1\b", re.S)


def from_text(text: str, origin: str) -> List[SqlSource]:
    """Shape-only SQL candidates from free text (code, heredocs, quoted strings)."""
    if not looks_destructive(text):
        return []
    out: List[SqlSource] = []
    seen = set()

    def add(chunk: str):
        chunk = chunk.strip()
        if chunk and chunk not in seen and looks_destructive(chunk):
            seen.add(chunk)
            out.append(SqlSource(sql=chunk, origin=origin))

    for m in _HEREDOC.finditer(text):
        add(m.group(2))
    for m in _STRING_LIT.finditer(text):
        lit = next(g for g in m.groups() if g is not None)
        add(lit.replace('\\"', '"').replace("\\'", "'"))
    if not out:
        add(text)
    return out


def from_tool_call(tool_name: str, args: Dict[str, Any], cwd: str) -> List[SqlSource]:
    if not isinstance(args, dict):
        return []
    if tool_name == "terminal" and isinstance(args.get("command"), str):
        workdir = args.get("workdir")
        base = _resolve(workdir, cwd) if isinstance(workdir, str) and workdir else cwd
        return from_command(args["command"], base)
    if tool_name == "execute_code" and isinstance(args.get("code"), str):
        return from_text(args["code"], origin="execute_code")
    # Any tool (MCP database servers etc.) passing SQL in a conventional argument.
    out: List[SqlSource] = []
    for key in SQL_ARG_NAMES:
        val = args.get(key)
        if isinstance(val, str) and looks_destructive(val):
            out.append(SqlSource(sql=val, origin=tool_name))
    return out
