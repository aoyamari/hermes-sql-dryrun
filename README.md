# sql-dryrun

**Know how many rows a query will hit before your agent runs it.**

Hermes asks for approval on `DROP TABLE`, `TRUNCATE` and `DELETE FROM` with no `WHERE` — it matches the *shape* of the command. sql-dryrun checks the *impact*: it asks the database (read-only) how many rows a `DELETE`/`UPDATE` would actually touch, and puts that number in front of you before anything changes.

## What it catches that shape-matching misses

Same SQLite file, 500 users, 12,850 orders. Left: Hermes' built-in detector. Right: sql-dryrun.

| Command the agent runs | Built-in | sql-dryrun |
|---|---|---|
| `DELETE FROM orders WHERE id = 7` | runs | runs (1 row) |
| `DELETE FROM users WHERE 1=1` | **runs** | approval: *WHERE is always true — every row in users (500)* |
| `UPDATE users SET active=0` | **runs** | approval: *UPDATE with no WHERE — every row in users (500)* |
| `DELETE FROM orders WHERE created_at < '2030-01-01'` | **runs** | approval: *WHERE matches ALL 12,850 rows in orders* |
| `DELETE FROM users; SELECT * FROM orders WHERE id=1` | **runs** | approval: *DELETE with no WHERE — every row in users (500)* |

On Postgres (250,000 orders):

```
sql-dryrun checked this SQL before it runs:
• DELETE FROM orders WHERE created_at < '2025-12-01'
  where: psql
  ⚠ 228,789 rows would change in orders (91.5% of the table), over the 100-row limit
  impact: 228,789 of 250,000 rows
```

## How it works

1. A `pre_tool_call` hook looks at `terminal` and `execute_code` calls, plus any tool that passes SQL in a `sql` / `query` / `statement` argument (MCP database servers).
2. It finds SQL fed to `sqlite3`, `psql`, `mysql` or `mariadb` — inline (`-c`, `-e`, positional), heredoc (`<<SQL`) or piped (`echo "…" | sqlite3 db`).
3. Each `DELETE` / `UPDATE` / `DROP TABLE` / `TRUNCATE` / `ALTER TABLE … DROP COLUMN` is split out (quotes, comments and `;` handled), and its `WHERE` is re-used in a `SELECT COUNT(*)`:
   - **SQLite** — opened with `mode=ro`, in-process.
   - **Postgres** — `psql` with `default_transaction_read_only=on` and a statement timeout.
   - **MySQL / MariaDB** — inside `START TRANSACTION READ ONLY … ROLLBACK`.
4. Flagged statements go to Hermes' normal approval prompt (or are blocked, if you choose). Safe ones run with no prompt at all.

A statement is flagged when it has no `WHERE`, a `WHERE` that is always true (`1=1`, `true`, `id=id`, `… OR 1=1`), a `WHERE` that matches every row, or touches more rows than `row_threshold`. `DROP` / `TRUNCATE` / `DROP COLUMN` are always flagged, with the row count of what's lost.

When there's no database to count in (SQL inside Python code, a remote MCP tool), it still flags by shape — including the `UPDATE`-without-`WHERE` and `1=1` cases Hermes lets through.

## Agent tool and command

- **`sql_impact`** — the agent can dry-run a statement before writing it: `{"sql": "UPDATE users SET active=0 WHERE id <= 40", "sqlite_db": "shop.db"}` → `rows_affected: 40, rows_in_table: 500`.
- **`/sql-dryrun`** — current settings and the last checks this session.

## Install

```bash
hermes plugins install aoyamari/hermes-sql-dryrun
hermes plugins enable sql-dryrun
```

## Settings

`plugins.entries.sql-dryrun.settings` in `config.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `row_threshold` | `100` | A `WHERE`-qualified `DELETE`/`UPDATE` touching more rows than this needs approval |
| `mode` | `approve` | `approve` = Hermes approval prompt, `block` = refuse and tell the agent why |
| `count_timeout_seconds` | `5` | Max time for the count query (0.5–20) |
| `flag_uncounted` | `false` | Also ask approval when a `WHERE`-qualified statement couldn't be counted |

## Disclosure

Reads the tool arguments of `terminal`, `execute_code` and tools with a `sql`/`query`/`statement` argument. When a destructive statement targets a database it can reach, it runs **read-only** `SELECT COUNT(*)` queries against it:

- **SQLite** — in-process, `mode=ro`, `trusted_schema=OFF`.
- **Postgres / MySQL / MariaDB** — the system client, under strict rules:
  - **Which binary:** only a bare `psql` / `mysql` / `mariadb` token, resolved with `shutil.which()`. A path (`./psql`, `/tmp/x/psql`) or a PATH hit inside the agent's working tree is never run — the statement is flagged by shape instead.
  - **Which environment:** `PATH`, `HOME`, `LANG`, `LC_*`, `TZ`, plus libpq `PG*` variables (never `PGOPTIONS`) or `MYSQL_PWD` / `MYSQL_HOST` / `MYSQL_TCP_PORT` / `MYSQL_UNIX_PORT`. No provider API keys or anything else. `$DATABASE_URL` is expanded only when it is the whole argument.
  - **Which flags:** connection flags only (`psql -h -p -U -d`, a dbname/URI; `mysql -h -P -u -D -S --defaults-file -pVALUE`, a database). Any other flag, a conninfo/URI with `options=`, a password prompt, or a `--defaults-file` inside the working tree → no count.
  - **Read-only, checked:** Postgres runs `BEGIN TRANSACTION READ ONLY`, then `SHOW transaction_read_only` must return `on` before any count is trusted; `PGOPTIONS` is set by the plugin, not inherited. MySQL runs inside `START TRANSACTION READ ONLY … ROLLBACK`. Both with a timeout and no password prompt.
- **Where:** counts only run when the terminal backend is `local`. On docker / ssh / modal / daytona the host's database isn't the sandbox's, so statements are flagged by shape only.

No network calls of its own, no files written, no data changed, nothing stored; the flagged SQL appears in the approval message. Not counted: statements with CTEs or joins (`USING`, `UPDATE … FROM`, multi-table) — those are still flagged by shape.

## Tests

```bash
python -m pytest tests
```

MIT © Aoyama
