"""Dependency-free SQL statement analysis.

Not a full SQL parser: it finds the destructive statements an agent typically
writes (DELETE, UPDATE, DROP, TRUNCATE, ALTER ... DROP COLUMN), the target
table, and the top-level WHERE / LIMIT clauses, so the counter can ask the
database how many rows the statement really touches.

Anything it cannot read with confidence (CTEs, multi-table joins, USING/FROM
joins) is marked ``complex``: the policy still flags the statement on its
shape, it just doesn't try to count rows for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

_IDENT_PART = r'(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)'
IDENT = rf"{_IDENT_PART}(?:\s*\.\s*{_IDENT_PART})*"

# Words that can follow a table name and are therefore never an alias.
_NOT_ALIAS = {
    "where", "set", "using", "returning", "order", "limit", "join", "inner",
    "left", "right", "full", "cross", "natural", "straight_join", "on",
    "from", "partition", "with", "cascade", "restrict",
}


@dataclass
class Finding:
    kind: str                       # DELETE | UPDATE | DROP | TRUNCATE | ALTER_DROP
    table: str = ""
    alias: str = ""
    where: Optional[str] = None     # None = no WHERE clause at all
    limit: Optional[int] = None
    complex: bool = False           # joins / CTEs: no reliable row count
    tautology: bool = False         # WHERE that is always true (1=1, x=x, true, ... OR 1=1)
    statement: str = ""
    detail: str = ""                # e.g. "DROP TABLE", "DROP COLUMN email"

    @property
    def has_where(self) -> bool:
        return self.where is not None and self.where.strip() != ""


# ── Lexing helpers ─────────────────────────────────────────────────────────

def _scan(sql: str):
    """Yield (index, char, depth, in_code) — in_code is False inside quotes/comments."""
    i, n, depth = 0, len(sql), 0
    while i < n:
        c = sql[i]
        two = sql[i:i + 2]
        if two == "--":
            j = sql.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c in ("'", '"', "`"):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:   # doubled quote escape
                        j += 2
                        continue
                    break
                if sql[j] == "\\" and c == "'":
                    j += 2
                    continue
                j += 1
            yield i, c, depth, False
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                i = n if j == -1 else j + len(tag)
                continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        yield i, c, depth, True
        i += 1


def strip_comments(sql: str) -> str:
    """Remove -- and /* */ comments, keeping quoted text intact."""
    n = len(sql)
    res = []
    i = 0
    quote = None
    while i < n:
        c = sql[i]
        if quote:
            res.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            quote = c
            res.append(c)
            i += 1
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            res.append(" ")
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            res.append(" ")
            continue
        res.append(c)
        i += 1
    return "".join(res)


def split_statements(sql: str) -> List[str]:
    sql = strip_comments(sql)
    parts, start = [], 0
    for idx, c, depth, code in _scan(sql):
        if code and c == ";" and depth == 0:
            parts.append(sql[start:idx])
            start = idx + 1
    parts.append(sql[start:])
    return [re.sub(r"\s+", " ", p).strip() for p in parts if p.strip()]


def _top_level_keywords(text: str, words: Tuple[str, ...]) -> List[Tuple[int, str]]:
    """Positions of the given keywords at paren depth 0 and outside quotes."""
    hits = []
    code_mask = [False] * len(text)
    depth_at = [0] * len(text)
    for idx, _c, depth, code in _scan(text):
        code_mask[idx] = code
        depth_at[idx] = depth
    pattern = re.compile(r"\b(" + "|".join(w.replace(" ", r"\s+") for w in words) + r")\b", re.I)
    for m in pattern.finditer(text):
        i = m.start()
        if code_mask[i] and depth_at[i] == 0:
            hits.append((i, re.sub(r"\s+", " ", m.group(1)).upper()))
    return hits


def _clause(rest: str, start_kw: str, stop_kws: Tuple[str, ...]) -> Optional[str]:
    hits = _top_level_keywords(rest, (start_kw,) + stop_kws)
    begin = None
    for pos, kw in hits:
        if kw == start_kw and begin is None:
            begin = pos + len(rest[pos:].split(None, 1)[0])
            continue
        if begin is not None and kw in stop_kws and pos > begin:
            return rest[begin:pos].strip()
    if begin is None:
        return None
    return rest[begin:].strip()


def _limit(rest: str) -> Optional[int]:
    m = re.search(r"\bLIMIT\s+(\d+)\s*$", rest, re.I)
    return int(m.group(1)) if m else None


# ── Tautology detection ────────────────────────────────────────────────────

_ALWAYS_TRUE = {"1", "true", "not false", "not 0", "1=1", "0=0", "1<>0", "0<>1", "1!=0",
                "1>0", "true=true", "1 is not null", "'1'='1'"}


def _strip_parens(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth, ok = 0, True
        for i, c in enumerate(expr):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and i != len(expr) - 1:
                    ok = False
                    break
        if not ok:
            break
        expr = expr[1:-1].strip()
    return expr


def _split_top(expr: str, word: str) -> List[str]:
    hits = [p for p, _ in _top_level_keywords(expr, (word,))]
    parts, start = [], 0
    for p in hits:
        parts.append(expr[start:p])
        start = p + len(word)
    parts.append(expr[start:])
    return [x.strip() for x in parts if x.strip()]


def _term_always_true(term: str) -> bool:
    t = _strip_parens(term)
    compact = re.sub(r"\s+", "", t).lower()
    spaced = re.sub(r"\s+", " ", t).lower()
    if compact in {re.sub(r"\s+", "", x) for x in _ALWAYS_TRUE} or spaced in _ALWAYS_TRUE:
        return True
    m = re.fullmatch(r"(.+?)\s*(=|>=|<=|<=>|\bis\b)\s*(.+)", t, re.I)
    if m and m.group(1).strip().lower() == m.group(3).strip().lower():
        lhs = m.group(1).strip()
        # x = x is true for every row where x is not NULL; literals always.
        return True if lhs else False
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(=|<>|!=|>|<|>=|<=)\s*(-?\d+(?:\.\d+)?)", t)
    if m:
        a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
        return {"=": a == b, "<>": a != b, "!=": a != b, ">": a > b, "<": a < b,
                ">=": a >= b, "<=": a <= b}[op]
    m = re.fullmatch(r"('[^']*')\s*(=|<>|!=)\s*('[^']*')", t)
    if m:
        return (m.group(1) == m.group(3)) == (m.group(2) == "=")
    if " and " in f" {spaced} ":
        conj = _split_top(t, "AND")
        if len(conj) > 1:
            return all(_term_always_true(c) for c in conj)
    return False


def is_tautology(where: Optional[str]) -> bool:
    if where is None:
        return False
    expr = _strip_parens(where)
    if not expr:
        return True
    return any(_term_always_true(d) for d in _split_top(expr, "OR"))


# ── Statement analysis ─────────────────────────────────────────────────────

_DELETE_RE = re.compile(
    rf"^DELETE\s+(?:(?:LOW_PRIORITY|QUICK|IGNORE)\s+)*FROM\s+(?:ONLY\s+)?(?P<table>{IDENT})\*?"
    rf"(?:\s+(?:AS\s+)?(?P<alias>{_IDENT_PART}))?(?P<rest>(?:\s.*)?)$", re.I | re.S)
_UPDATE_RE = re.compile(
    rf"^UPDATE\s+(?:(?:LOW_PRIORITY|IGNORE|ONLY)\s+|OR\s+\w+\s+)*(?P<table>{IDENT})\*?"
    rf"(?:\s+(?:AS\s+)?(?P<alias>{_IDENT_PART}))?\s+(?P<rest>.*)$", re.I | re.S)
_DROP_RE = re.compile(
    rf"^DROP\s+(?P<what>TABLE|DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?(?P<table>{IDENT})", re.I)
_TRUNC_RE = re.compile(rf"^TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(?P<table>{IDENT})", re.I)
_ALTER_RE = re.compile(
    rf"^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<table>{IDENT})\s+.*?\bDROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(?P<col>{_IDENT_PART})",
    re.I | re.S)


def _alias(raw: Optional[str]) -> str:
    if not raw or raw.lower() in _NOT_ALIAS:
        return ""
    return raw


def analyze_statement(stmt: str) -> Optional[Finding]:
    s = stmt.strip().rstrip(";").strip()
    if not s:
        return None
    head = s.split(None, 1)[0].upper()

    if head == "WITH":
        kws = _top_level_keywords(s, ("DELETE", "UPDATE"))
        if kws:
            return Finding(kind=kws[-1][1], complex=True, statement=s,
                           detail="statement with CTE (WITH ...)",
                           where=_clause(s[kws[-1][0]:], "WHERE", ("RETURNING", "ORDER BY", "LIMIT")))
        return None

    if head == "DELETE":
        m = _DELETE_RE.match(s)
        if not m:
            # MySQL multi-table "DELETE t1, t2 FROM ..." etc.
            return Finding(kind="DELETE", complex=True, statement=s, detail="multi-table DELETE",
                           where=_clause(s, "WHERE", ("ORDER BY", "LIMIT", "RETURNING")))
        alias = m.group("alias")
        rest = m.group("rest") or ""
        if alias and alias.lower() in _NOT_ALIAS:
            rest = " " + alias + rest
            alias = ""
        f = Finding(kind="DELETE", table=m.group("table"), alias=_alias(alias), statement=s)
        f.where = _clause(rest, "WHERE", ("RETURNING", "ORDER BY", "LIMIT"))
        f.limit = _limit(rest)
        if _top_level_keywords(rest, ("USING", "JOIN")):
            f.complex, f.detail = True, "DELETE with USING/JOIN"
        f.tautology = is_tautology(f.where)
        return f

    if head == "UPDATE":
        m = _UPDATE_RE.match(s)
        if not m:
            return Finding(kind="UPDATE", complex=True, statement=s, detail="unparsed UPDATE",
                           where=_clause(s, "WHERE", ("ORDER BY", "LIMIT", "RETURNING")))
        alias = m.group("alias")
        rest = m.group("rest")
        if alias and alias.lower() in _NOT_ALIAS:
            rest = alias + " " + rest
            alias = ""
        f = Finding(kind="UPDATE", table=m.group("table"), alias=_alias(alias), statement=s)
        if not re.match(r"SET\b", rest, re.I):
            f.complex, f.detail = True, "multi-table UPDATE"
        f.where = _clause(rest, "WHERE", ("RETURNING", "ORDER BY", "LIMIT"))
        f.limit = _limit(rest)
        # Postgres/SQLite "UPDATE t SET ... FROM other WHERE ..." is a join update.
        hits = _top_level_keywords(rest, ("FROM", "WHERE"))
        if hits and hits[0][1] == "FROM":
            f.complex, f.detail = True, "UPDATE ... FROM join"
        f.tautology = is_tautology(f.where)
        return f

    if head == "DROP":
        m = _DROP_RE.match(s)
        if m:
            return Finding(kind="DROP", table=m.group("table"), statement=s,
                           detail=f"DROP {m.group('what').upper()}",
                           complex=m.group("what").upper() != "TABLE")
        return None

    if head == "TRUNCATE":
        m = _TRUNC_RE.match(s)
        if m:
            return Finding(kind="TRUNCATE", table=m.group("table"), statement=s, detail="TRUNCATE")
        return None

    if head == "ALTER":
        m = _ALTER_RE.match(s)
        if m:
            return Finding(kind="ALTER_DROP", table=m.group("table"), statement=s,
                           detail=f"DROP COLUMN {m.group('col')}")
        return None

    return None


def analyze_sql(sql: str) -> List[Finding]:
    out = []
    for stmt in split_statements(sql):
        f = analyze_statement(stmt)
        if f:
            out.append(f)
    return out


DESTRUCTIVE_HINT = re.compile(
    r"\b(DELETE\s+FROM|DELETE\s+\w|UPDATE\s+\S+\s+(?:\S+\s+)?SET\b|UPDATE\s+\S+\s+(?:\S+\s+)?(?:INNER\s+|LEFT\s+)?JOIN\b|"
    r"DROP\s+(?:TABLE|DATABASE|SCHEMA)\b|TRUNCATE\b|ALTER\s+TABLE\b[^;]*\bDROP\b|WITH\b[^;]*\b(?:DELETE|UPDATE)\b)",
    re.I | re.S)


def looks_destructive(text: str) -> bool:
    return bool(text) and bool(DESTRUCTIVE_HINT.search(text))


# ── Is this WHERE safe to run before the user has approved anything? ──────
#
# The count executes model-written WHERE text ahead of the approval prompt, so
# it must be a plain predicate: comparisons, AND/OR, IN/EXISTS subqueries and a
# short list of pure built-in functions. A read-only transaction does not stop
# pg_reload_conf(), pg_terminate_backend(), dblink_exec(), SELECT ... INTO
# OUTFILE and friends, so anything outside the list means "don't count".

_SQL_WORDS = {
    "and", "or", "not", "in", "exists", "any", "all", "some", "select", "from", "where", "on", "as",
    "values", "case", "when", "then", "else", "between", "like", "ilike", "is", "join", "using",
    "union", "distinct", "by", "having", "limit", "offset", "over", "filter", "cast", "extract",
    "interval", "row", "array", "escape", "similar", "to", "end", "null", "true", "false",
}
_PURE_FUNCS = {
    # text
    "lower", "upper", "length", "char_length", "character_length", "trim", "ltrim", "rtrim", "btrim",
    "substr", "substring", "left", "right", "concat", "replace", "position", "strpos", "instr",
    "lpad", "rpad", "reverse", "initcap",
    # null / numeric
    "coalesce", "nullif", "ifnull", "nvl", "abs", "round", "floor", "ceil", "ceiling", "mod",
    "greatest", "least", "sign", "power",
    # date / time
    "now", "date", "time", "datetime", "julianday", "strftime", "date_trunc", "date_part",
    "to_date", "to_timestamp", "to_char", "date_add", "date_sub", "datediff", "timestampdiff",
    "year", "month", "day", "hour", "minute", "second", "curdate", "current_date",
    "current_timestamp", "unix_timestamp", "from_unixtime", "age", "make_date",
    # aggregates (inside subqueries)
    "count", "sum", "min", "max", "avg",
    # type names used with a length: varchar(10), numeric(10,2)
    "varchar", "char", "character", "numeric", "decimal", "int", "integer", "bigint", "smallint",
    "timestamp", "float", "double", "real", "text", "boolean", "bool",
}
_FORBIDDEN_WORDS = re.compile(r"\b(into|procedure|outfile|dumpfile|attach|pragma|call|do|execute|copy|load_file|"
                              r"lock|share|for\s+update)\b", re.I)
_CALL = re.compile(r"(?P<dot>\.\s*)?(?P<name>[A-Za-z_][\w]*)\s*\(")


def _mask_quoted(text: str):
    """Blank out '...', "..." and `...` regions (doubling is the only escape).

    Callers must already have refused backslashes and '$', which is what makes
    this agree with how SQLite, Postgres and MySQL all read the same text.
    Returns (masked, ok) — ok is False for an unterminated quote.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"', "`"):
            j = i + 1
            while j < n:
                if text[j] == c:
                    if j + 1 < n and text[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                return "", False
            out.append(c + "_" * (j - i - 1) + c)
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), True


def where_uncountable(where: Optional[str]) -> str:
    """Reason this WHERE must not be executed for a count, or '' if it is a plain predicate."""
    if not where:
        return ""
    if ";" in where or "\\" in where:
        return "statement contains ';' or a backslash"
    if "$" in where:
        return "WHERE uses '$' (dollar quoting / parameters)"
    if "/*" in where or "--" in where or "#" in where:
        return "WHERE contains a comment marker"
    masked, ok = _mask_quoted(where)
    if not ok:
        return "WHERE has an unterminated quote"
    if re.search(r"[\"`]\s*\(", masked):
        return "WHERE calls a quoted function name"
    m = _FORBIDDEN_WORDS.search(masked)
    if m:
        return f"WHERE contains {m.group(1).upper()}"
    for m in _CALL.finditer(masked):
        name = m.group("name").lower()
        if m.group("dot"):
            return f"WHERE calls a schema-qualified function ({name})"
        if name not in _SQL_WORDS and name not in _PURE_FUNCS:
            return f"WHERE calls {name}(), which isn't on the pure-function list"
    return ""
