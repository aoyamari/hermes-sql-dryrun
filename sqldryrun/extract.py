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
from typing import Any, Dict, List, Optional, Tuple

from .parse import looks_destructive

SQL_ARG_NAMES = ("sql", "query", "statement", "statements", "sql_query", "command_sql")


@dataclass
class Target:
    engine: str                     # sqlite | postgres | mysql
    client: str = ""                # executable token as written (psql, mysql, mariadb, ./psql, ...)
    db_path: str = ""               # sqlite only, resolved absolute path
    conn_args: List[str] = field(default_factory=list)   # allowlisted connection flags, canonical --opt=value
    env: Dict[str, str] = field(default_factory=dict)    # allowlisted PG*/MYSQL_* assignments from the command
    tree: List[str] = field(default_factory=list)        # working-tree dirs: a client resolving inside is refused
    uncountable: str = ""           # non-empty = don't count, flag by shape only (reason shown to the user)


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


_ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)

# Environment the count may inherit from the agent's command (`PGPASSWORD=x psql ...`).
# PGOPTIONS is never taken: it could switch the read-only session off.
_MYSQL_ENV = {"MYSQL_PWD", "MYSQL_HOST", "MYSQL_TCP_PORT", "MYSQL_UNIX_PORT"}


def allowed_env_key(engine: str, key: str) -> bool:
    if engine == "postgres":
        return key.startswith("PG") and key != "PGOPTIONS"
    if engine == "mysql":
        return key in _MYSQL_ENV
    return False


def _strip_env_prefix(seg: List[str]) -> Tuple[List[str], Dict[str, str]]:
    """Drop leading VAR=value / sudo / env words; return (rest, assignments)."""
    i, assigns = 0, {}
    while i < len(seg):
        m = _ASSIGN.match(seg[i])
        if not m:
            break
        assigns[m.group(1)] = m.group(2)
        i += 1
    while i < len(seg) and seg[i] in ("sudo", "env", "time", "nice", "command", "exec"):
        i += 1
        while i < len(seg) and (seg[i].startswith("-") or _ASSIGN.match(seg[i])):
            m = _ASSIGN.match(seg[i])
            if m:
                assigns[m.group(1)] = m.group(2)
            i += 1
    return seg[i:], assigns


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


class _Args:
    """Tiny getopt-ish walker: yields (flag, value) / (None, positional)."""

    def __init__(self, args: List[str], short_val: Dict[str, str], long_val: set):
        self.args, self.short_val, self.long_val = args, short_val, long_val

    def __iter__(self):
        args, i = self.args, 0
        while i < len(args):
            a = args[i]
            if a.startswith("--") and len(a) > 2:
                name, eq, val = a.partition("=")
                if eq:
                    yield name, val
                elif name in self.long_val and i + 1 < len(args):
                    yield name, args[i + 1]
                    i += 1
                else:
                    yield name, None
            elif a.startswith("-") and len(a) > 1:
                flag = a[:2]
                if flag in self.short_val:
                    if len(a) > 2:
                        yield flag, a[2:]
                    elif i + 1 < len(args):
                        yield flag, args[i + 1]
                        i += 1
                    else:
                        yield flag, None
                else:
                    # bundled boolean flags (-qAt) — report each
                    for ch in a[1:]:
                        yield "-" + ch, None
            else:
                yield None, a
            i += 1


def _unquote_all(v: str) -> str:
    from urllib.parse import unquote
    for _ in range(3):                      # nested encodings: %256F -> %6F -> o
        nv = unquote(v)
        if nv == v:
            break
        v = nv
    return v


_OPTIONS_KEY = re.compile(r"(?:^|[\s?&])options\s*=", re.I)
_VAR_REF = re.compile(r"^\$(?:\{(\w+)\}|(\w+))$")


def _expand(value: str, assigns: Dict[str, str]) -> Tuple[Optional[str], str]:
    """Expand a bare $DATABASE_URL; refuse any other shell expansion."""
    m = _VAR_REF.match(value)
    if m:
        name = m.group(1) or m.group(2)
        if name == "DATABASE_URL" or name.startswith(("PG", "MYSQL_")):
            v = assigns.get(name, os.environ.get(name))
            if v is None:
                return None, f"${name} is not set"
            return v, ""
        return None, f"connection uses ${name}"
    if "$" in value or "`" in value:
        return None, "connection value uses shell expansion"
    return value, ""


# psql: SQL flags, connection flags we pass on, output flags we ignore. Anything else → no count.
_PSQL_SHORT_VAL = {"-c": "sql", "-h": "--host", "-p": "--port", "-U": "--username", "-d": "--dbname",
                   "-f": "ignore", "-o": "ignore", "-L": "ignore", "-v": "ignore", "-P": "ignore",
                   "-F": "ignore", "-R": "ignore", "-T": "ignore"}
_PSQL_LONG = {"--command": "sql", "--host": "--host", "--port": "--port", "--username": "--username",
              "--dbname": "--dbname", "--file": "ignore", "--output": "ignore", "--log-file": "ignore",
              "--set": "ignore", "--variable": "ignore", "--pset": "ignore", "--field-separator": "ignore",
              "--record-separator": "ignore", "--table-attr": "ignore"}
_PSQL_BOOL = {"-q", "--quiet", "-A", "--no-align", "-t", "--tuples-only", "-x", "--expanded", "-X",
              "--no-psqlrc", "-a", "--echo-all", "-e", "--echo-queries", "-E", "--echo-hidden", "-n",
              "--no-readline", "-H", "--html", "-1", "--single-transaction", "-w", "--no-password", "-b",
              "--echo-errors", "-S", "--single-line", "-s", "--single-step", "-z", "--field-separator-zero",
              "-0", "--record-separator-zero", "--csv"}


def _parse_psql(args: List[str], client: str, assigns: Dict[str, str]) -> Optional[SqlSource]:
    sqls, conn, positional, why = [], [], [], ""
    for flag, val in _Args(args, _PSQL_SHORT_VAL, set(_PSQL_LONG)):
        if flag is None:
            positional.append(val)
            continue
        kind = _PSQL_SHORT_VAL.get(flag) if not flag.startswith("--") else _PSQL_LONG.get(flag)
        if kind == "sql":
            if val is not None:
                sqls.append(val)
        elif kind == "ignore" or (kind is None and flag in _PSQL_BOOL):
            continue
        elif kind:
            if val is None:
                why = why or f"psql {flag} without a value"
                continue
            v, err = _expand(val, assigns)
            if v is None:
                why = why or err
            else:
                conn.append(f"{kind}={v}")
        else:
            why = why or f"psql flag {flag} is not on the allowlist"
    if not sqls:
        return None
    if len(positional) > 2:
        why = why or "unexpected psql arguments"
    for p in positional:
        v, err = _expand(p, assigns)
        if v is None:
            why = why or err
        elif v.startswith("-"):
            why = why or "unexpected psql argument"
        else:
            conn.append(v)
    for c in conn:
        val = c.split("=", 1)[1] if c.startswith("--") else c
        # libpq percent-decodes URI keys, so check the decoded text too (%6Fptions=...).
        if _OPTIONS_KEY.search(val) or _OPTIONS_KEY.search(_unquote_all(val)):
            why = why or "connection string sets options="
    env = {k: v for k, v in assigns.items() if allowed_env_key("postgres", k)}
    return SqlSource(sql="; ".join(sqls), origin="psql",
                     target=Target(engine="postgres", client=client, conn_args=conn, env=env, uncountable=why))


_MY_SHORT_VAL = {"-e": "sql", "-h": "--host", "-P": "--port", "-u": "--user", "-D": "--database",
                 "-S": "--socket"}
_MY_LONG = {"--execute": "sql", "--host": "--host", "--port": "--port", "--user": "--user",
            "--database": "--database", "--socket": "--socket"}
_MY_BOOL = {"-N", "--skip-column-names", "-B", "--batch", "-s", "--silent", "-t", "--table", "-v",
            "--verbose", "-f", "--force", "-r", "--raw", "-E", "--vertical", "-n", "--unbuffered", "-q",
            "--quick", "--column-names"}


def _parse_mysql(args: List[str], client: str, cwd: str, assigns: Dict[str, str]) -> Optional[SqlSource]:
    sqls, conn, positional, why = [], [], [], ""
    # -p is optional-argument: only the attached form (-pSECRET) carries a value.
    cleaned = []
    for a in args:
        if a.startswith("-p") and not a.startswith("--"):
            if len(a) > 2:
                conn.append("--password=" + a[2:])
            else:
                why = why or "mysql -p would prompt for a password"
            continue
        if a == "--password":
            why = why or "mysql --password would prompt for a password"
            continue
        if a.startswith("--password="):
            conn.append(a)
            continue
        cleaned.append(a)
    for flag, val in _Args(cleaned, _MY_SHORT_VAL, set(_MY_LONG)):
        if flag is None:
            positional.append(val)
            continue
        kind = _MY_SHORT_VAL.get(flag) if not flag.startswith("--") else _MY_LONG.get(flag)
        if kind == "sql":
            if val is not None:
                sqls.append(val)
        elif kind is None and flag in _MY_BOOL:
            continue
        elif kind:
            if val is None:
                why = why or f"{flag} without a value"
                continue
            v, err = _expand(val, assigns)
            if v is None:
                why = why or err
            else:
                conn.append(f"{kind}={v}")
        else:
            why = why or f"mysql flag {flag} is not on the allowlist"
    if not sqls:
        return None
    if len(positional) > 1:
        why = why or "unexpected mysql arguments"
    for p in positional:
        v, err = _expand(p, assigns)
        if v is None:
            why = why or err
        elif v.startswith("-"):
            why = why or "unexpected mysql argument"
        else:
            conn.append(f"--database={v}")
    env = {k: v for k, v in assigns.items() if allowed_env_key("mysql", k)}
    return SqlSource(sql="; ".join(sqls), origin=os.path.basename(client),
                     target=Target(engine="mysql", client=client, conn_args=conn, env=env, uncountable=why))


_CLIENTS = ("sqlite3", "sqlite", "psql", "mysql", "mariadb")


def _client_source(exe_token: str, args: List[str], cwd: str, piped_sql: Optional[str] = None,
                   assigns: Optional[Dict[str, str]] = None) -> Optional[SqlSource]:
    exe = os.path.basename(exe_token)
    assigns = assigns or {}
    if piped_sql is not None:
        if exe in ("sqlite3", "sqlite"):
            args = args + [piped_sql]
        elif exe == "psql":
            args = args + ["-c", piped_sql]
        elif exe in ("mysql", "mariadb"):
            args = args + ["-e", piped_sql]
    src = None
    if exe in ("sqlite3", "sqlite"):
        src = _parse_sqlite(args, exe_token, cwd)
    elif exe == "psql":
        src = _parse_psql(args, exe_token, assigns)
    elif exe in ("mysql", "mariadb"):
        src = _parse_mysql(args, exe_token, cwd, assigns)
    if src and src.target:
        src.target.tree = [cwd]
    return src


_HEREDOC_CLIENT = re.compile(
    r"(?P<pre>(?:^|[\n;&|(])\s*(?:[A-Za-z_]\w*=\S+\s+)*)(?P<exe>\S*(?:sqlite3?|psql|mysql|mariadb))\b"
    r"(?P<args>[^\n|;&]*?)<<-?\s*['\"]?(?P<tag>\w+)['\"]?[^\n]*\n(?P<body>.*?)\n\s*(?P=tag)\b", re.S)


def from_command(command: str, cwd: str) -> List[SqlSource]:
    """SQL sources inside a shell command string."""
    found: List[SqlSource] = []

    # 1. Heredocs fed to a client: sqlite3 shop.db <<'SQL' ... SQL
    for m in _HEREDOC_CLIENT.finditer(command):
        args = _tokens(re.sub(r"[<>]\s*\S+", "", m.group("args"))) or []
        _rest, assigns = _strip_env_prefix(_tokens(m.group("pre").strip(" \n;&|(")) or [])
        src = _client_source(m.group("exe"), args, cwd, piped_sql=m.group("body"), assigns=assigns)
        if src and looks_destructive(src.sql):
            found.append(src)
    if found:
        return found

    # 2. Inline SQL (-c / -e / positional), or `echo "SQL" | client`.
    tokens = _tokens(command)
    if tokens:
        segs = _segments(tokens)
        for idx, seg in enumerate(segs):
            seg, assigns = _strip_env_prefix(seg)
            if not seg or os.path.basename(seg[0]) not in _CLIENTS:
                continue
            src = _client_source(seg[0], seg[1:], cwd, assigns=assigns)
            if src is None and idx > 0:
                prev, _ = _strip_env_prefix(segs[idx - 1])
                if prev and os.path.basename(prev[0]) in ("echo", "printf", "cat"):
                    body = " ".join(a for a in prev[1:] if not a.startswith("-"))
                    if looks_destructive(body):
                        src = _client_source(seg[0], seg[1:], cwd, piped_sql=body, assigns=assigns)
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


def restrict_to_backend(sources: List[SqlSource], backend: str) -> List[SqlSource]:
    """Counts read the host's database; on a sandboxed backend that's the wrong one."""
    if backend != "local":
        for s in sources:
            if s.target and not s.target.uncountable:
                s.target.uncountable = f"terminal backend is {backend}; row counts only run for local"
    return sources


def from_tool_call(tool_name: str, args: Dict[str, Any], cwd: str, backend: str = "local") -> List[SqlSource]:
    if not isinstance(args, dict):
        return []
    if tool_name == "terminal" and isinstance(args.get("command"), str):
        workdir = args.get("workdir")
        base = _resolve(workdir, cwd) if isinstance(workdir, str) and workdir else cwd
        srcs = from_command(args["command"], base)
        for s in srcs:
            if s.target and cwd not in s.target.tree:
                s.target.tree.append(cwd)
        return restrict_to_backend(srcs, backend)
    if tool_name == "execute_code" and isinstance(args.get("code"), str):
        return from_text(args["code"], origin="execute_code")
    # Any tool (MCP database servers etc.) passing SQL in a conventional argument.
    out: List[SqlSource] = []
    for key in SQL_ARG_NAMES:
        val = args.get(key)
        if isinstance(val, str) and looks_destructive(val):
            out.append(SqlSource(sql=val, origin=tool_name))
    return out
