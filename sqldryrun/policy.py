"""Turn findings + row counts into a decision: let it run, ask the human, or block."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .count import UNSAFE_CHARS, Count, count_rows
from .extract import SqlSource
from .parse import Finding, analyze_sql


@dataclass
class Settings:
    row_threshold: int = 100
    mode: str = "approve"               # approve | block
    count_timeout_seconds: float = 5.0
    flag_uncounted: bool = False        # flag WHERE-qualified statements we could not count

    @classmethod
    def from_getter(cls, get) -> "Settings":
        s = cls()
        try:
            s.row_threshold = max(0, int(get("row_threshold", s.row_threshold)))
        except (TypeError, ValueError):
            pass
        mode = str(get("mode", s.mode) or s.mode).strip().lower()
        s.mode = mode if mode in ("approve", "block") else "approve"
        try:
            s.count_timeout_seconds = min(20.0, max(0.5, float(get("count_timeout_seconds",
                                                                   s.count_timeout_seconds))))
        except (TypeError, ValueError):
            pass
        s.flag_uncounted = bool(get("flag_uncounted", s.flag_uncounted))
        return s


@dataclass
class Assessment:
    finding: Finding
    source: SqlSource
    count: Count
    reasons: List[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.reasons)

    def to_dict(self) -> Dict[str, Any]:
        f, c = self.finding, self.count
        return {
            "statement": f.statement,
            "kind": f.kind,
            "table": f.table,
            "has_where": f.has_where,
            "where_always_true": f.tautology,
            "limit": f.limit,
            "rows_affected": c.affected,
            "rows_in_table": c.total,
            "count_note": c.error or None,
            "origin": self.source.origin,
            "flagged": self.flagged,
            "reasons": self.reasons,
        }


def _n(x: Optional[int]) -> str:
    return "?" if x is None else f"{x:,}"


def _short(stmt: str, limit: int = 160) -> str:
    return stmt if len(stmt) <= limit else stmt[: limit - 1] + "…"


def assess(src: SqlSource, settings: Settings) -> List[Assessment]:
    out = []
    for f in analyze_sql(src.sql):
        c = count_rows(f, src.target, settings.count_timeout_seconds)
        a = Assessment(finding=f, source=src, count=c)
        r = a.reasons
        what = f"{f.table}" if f.table else "the target table"
        if f.kind == "DROP":
            r.append(f"{f.detail} {what}" + (f" — {_n(c.total)} rows gone" if c.total is not None else ""))
        elif f.kind == "TRUNCATE":
            r.append(f"TRUNCATE {what}" + (f" — {_n(c.total)} rows gone" if c.total is not None else ""))
        elif f.kind == "ALTER_DROP":
            r.append(f"{f.detail} on {what}" + (f" — data in {_n(c.total)} rows gone"
                                                  if c.total is not None else ""))
        else:
            if not f.has_where:
                r.append(f"{f.kind} with no WHERE — every row in {what}" +
                         (f" ({_n(c.total)})" if c.total is not None else ""))
            elif f.tautology:
                r.append(f"WHERE is always true ({_short(f.where, 40)}) — every row in {what}" +
                         (f" ({_n(c.total)})" if c.total is not None else ""))
            elif c.affected is not None:
                if c.total and c.affected == c.total and c.affected > 1:
                    r.append(f"WHERE matches ALL {_n(c.total)} rows in {what}")
                elif c.affected > settings.row_threshold:
                    pct = f" ({c.affected / c.total:.1%} of the table)" if c.total else ""
                    r.append(f"{_n(c.affected)} rows would change in {what}{pct}, "
                             f"over the {settings.row_threshold:,}-row limit")
            elif any(ch in f.statement for ch in UNSAFE_CHARS):
                r.append("contains ';' or a backslash inside the statement — not counted, "
                         "the database may read it as more than one statement")
            elif settings.flag_uncounted:
                r.append(f"couldn't count affected rows ({c.error})")
        out.append(a)
    return out


def assess_all(sources: List[SqlSource], settings: Settings) -> List[Assessment]:
    out = []
    for s in sources:
        out.extend(assess(s, settings))
    return out


def render(flagged: List[Assessment]) -> str:
    lines = ["sql-dryrun checked this SQL before it runs:"]
    for a in flagged:
        f, c = a.finding, a.count
        lines.append(f"• {_short(f.statement)}")
        lines.append(f"  where: {a.source.origin or 'unknown'}")
        for reason in a.reasons:
            lines.append(f"  ⚠ {reason}")
        if c.affected is not None and f.kind in ("DELETE", "UPDATE"):
            lines.append(f"  impact: {_n(c.affected)} of {_n(c.total)} rows")
        elif c.error and f.kind in ("DELETE", "UPDATE"):
            lines.append(f"  impact: unknown — {c.error}")
    return "\n".join(lines)


def directive(assessments: List[Assessment], settings: Settings) -> Optional[Dict[str, Any]]:
    flagged = [a for a in assessments if a.flagged]
    if not flagged:
        return None
    msg = render(flagged)
    key = hashlib.sha1("\n".join(a.finding.statement for a in flagged).encode()).hexdigest()[:12]
    if settings.mode == "block":
        return {"action": "block",
                "message": msg + "\nBlocked by sql-dryrun. Narrow the WHERE clause, or ask the "
                                 "user to confirm and run it themselves."}
    return {"action": "approve", "message": msg, "rule_key": f"sql-dryrun:{key}"}
