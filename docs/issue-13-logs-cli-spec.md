# Issue #13: `agentgate logs` CLI Command

**Status:** Spec ready · Implementation blocked on #12 (audit writer)  
**Depends on:** #12 (SQLite audit writer — must be merged first)  
**Estimated effort:** ~2 hours implementation + tests  

---

## 1. What This Is

Replace the `logs` stub in `cli.py` with a real command that reads the SQLite audit log and outputs filtered results as JSON lines to stdout. This is a read-only query tool — it never writes to the database.

## 2. Interface

```
agentgate logs [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tail N` | int (≥1) | None (all rows) | Show last N entries only |
| `--session ID` | string | None | Filter to entries matching this session ID |
| `--decision` | `allow` \| `block` | None | Filter by decision value |
| `--db PATH` | string | `agentgate_audit.db` | Path to the audit SQLite database |
| `--verify` | flag | False | Verify hash chain integrity and exit |

`--tail`, `--session`, and `--decision` compose with AND logic. All three can be used together.

### Output format

One JSON object per line to stdout (JSON Lines / NDJSON). Each line contains all columns from the `audit_log` table:

```jsonl
{"id":1,"timestamp":"2026-03-14T10:00:00+00:00","session_id":"abc-123","tool_name":"read_file","arguments":{"path":"/etc/passwd"},"decision":"block","matched_rule":"sandboxed-files","matched_detector":"path_traversal","message":"Path traversal sequence in param 'path'","prev_hash":"genesis","entry_hash":"a1b2c3..."}
{"id":2,"timestamp":"2026-03-14T10:00:01+00:00","session_id":"abc-123","tool_name":"read_file","arguments":{"path":"/data/workspace/q4.csv"},"decision":"allow","matched_rule":null,"matched_detector":null,"message":null,"prev_hash":"a1b2c3...","entry_hash":"d4e5f6..."}
```

Key details:
- `arguments` is parsed back from JSON string to a dict (not double-encoded)
- `null` values stay as JSON `null` (not omitted)
- Output order: ascending by `id` (chronological). `--tail` returns the *last* N in ascending order (not reversed).
- No trailing newline after the last line

### `--verify` mode

When `--verify` is passed, ignore all filter flags. Walk the full hash chain using `AuditWriter.verify_chain()` (or equivalent read-only logic). Print result to stderr and exit:

```
OK: 42 entries, chain intact
```
or
```
FAIL: chain broken (42 entries examined)
```

Exit code: 0 if intact, 1 if broken.

### Error cases

| Condition | Behavior |
|-----------|----------|
| DB file doesn't exist | Print `Error: Audit database not found: <path>` to stderr, exit 1 |
| DB exists but `audit_log` table missing | Print `Error: No audit_log table in <path>` to stderr, exit 1 |
| `--tail` with non-positive value | Click handles this (type=int, min=1) |
| No matching rows | Output nothing (empty stdout), exit 0 |

## 3. Implementation Plan

### File: `src/agentgate/cli.py`

Replace the `logs` stub. The command does direct SQLite reads — it does NOT instantiate `AuditWriter` (that's for writes). Open a read-only connection.

```python
@main.command()
@click.option("--tail", type=int, default=None, help="Show last N entries.")
@click.option("--session", type=str, default=None, help="Filter by session ID.")
@click.option("--decision", type=click.Choice(["allow", "block"]), default=None, help="Filter by decision.")
@click.option("--db", default="agentgate_audit.db", type=click.Path(), help="Path to audit database.")
@click.option("--verify", is_flag=True, default=False, help="Verify hash chain integrity and exit.")
def logs(tail, session, decision, db, verify):
```

### Query construction

Build a parameterized SQL query. Never interpolate user values into SQL.

```sql
-- Base query
SELECT id, timestamp, session_id, tool_name, arguments,
       decision, matched_rule, matched_detector, message,
       prev_hash, entry_hash
FROM audit_log
WHERE 1=1
  [AND session_id = ?]      -- if --session
  [AND decision = ?]        -- if --decision
ORDER BY id ASC
[LIMIT ?]                   -- if --tail, uses subquery or LIMIT+ORDER trick
```

For `--tail` with filters: the intent is "last N rows matching the filters." Use a subquery:

```sql
SELECT * FROM (
  SELECT ... FROM audit_log
  WHERE <filters>
  ORDER BY id DESC
  LIMIT ?
) sub ORDER BY id ASC
```

This gives the last N matching rows in chronological order.

### Row serialization

Each row becomes a dict. The `arguments` column is stored as a JSON string in SQLite — parse it back with `json.loads()` before emitting so the output contains a proper nested object, not a double-encoded string. If `json.loads()` fails on a row's arguments (shouldn't happen, but defensive), emit the raw string.

Nullable columns (`matched_rule`, `matched_detector`, `message`): emit as `null` in JSON.

Use `json.dumps(row, separators=(",", ":"))` for compact output (no extra whitespace). One `click.echo()` per line.

### Verify mode

For `--verify`, reuse the hash-chain verification logic. Two options:

**Option A (preferred):** Extract the verification logic from `AuditWriter.verify_chain()` into a standalone function (or just call it if the import is clean). The verify method already opens its own read-only connection, so there's no coupling to the writer thread.

**Option B:** Duplicate the ~15 lines of verification SQL+hash logic directly in the CLI. Acceptable given the simplicity.

Go with Option A — import `AuditWriter` just for verify, or better, extract `verify_chain` as a module-level function in `audit.py` that takes a `db_path` argument. This avoids instantiating the writer (which spawns a background thread).

### Suggested refactor in `audit.py`

Extract a standalone function:

```python
def verify_chain(db_path: str | Path) -> tuple[bool, int]:
    """Verify hash chain integrity of an audit database. Read-only."""
    # ... same logic as AuditWriter.verify_chain but takes a path
```

Keep `AuditWriter.verify_chain()` as a thin wrapper that calls this.

## 4. Test Plan

### File: `tests/test_cli_logs.py`

All tests use `tmp_path` for a scratch SQLite database. Pre-populate the DB using `AuditWriter` (write N entries, close, then run the CLI against the file). Use Click's `CliRunner` for invocation.

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_logs_no_db` | Missing DB file → stderr error, exit 1 |
| 2 | `test_logs_empty_db` | DB exists, table exists, 0 rows → empty stdout, exit 0 |
| 3 | `test_logs_all_entries` | No filters → all rows in JSON lines, chronological order |
| 4 | `test_logs_tail` | `--tail 2` on 5 entries → last 2 entries, chronological |
| 5 | `test_logs_session_filter` | `--session X` → only rows with that session_id |
| 6 | `test_logs_decision_filter` | `--decision block` → only block rows |
| 7 | `test_logs_combined_filters` | `--tail 1 --decision block --session X` → correct intersection |
| 8 | `test_logs_no_matches` | Filters that match nothing → empty stdout, exit 0 |
| 9 | `test_logs_arguments_parsed` | `arguments` field is a dict in output, not a double-encoded string |
| 10 | `test_logs_null_fields` | Allowed entry (no matched_rule) → `null` in JSON output |
| 11 | `test_logs_verify_intact` | `--verify` on valid DB → "OK" on stderr, exit 0 |
| 12 | `test_logs_verify_broken` | `--verify` on tampered DB → "FAIL" on stderr, exit 1 |
| 13 | `test_logs_db_option` | `--db /path/to/other.db` → reads from specified path |

### Helper: DB seeding

Write a `_seed_db` fixture that:
1. Creates an `AuditWriter` pointed at `tmp_path / "test_audit.db"`
2. Logs 5 entries: 3 allow, 2 block, across 2 session IDs
3. Calls `close()`
4. Returns the db path

## 5. Acceptance Criteria

- [ ] `agentgate logs` outputs valid JSON lines (one JSON object per line)
- [ ] `--tail N` returns the last N entries in chronological order
- [ ] `--session` and `--decision` filter correctly and compose with AND
- [ ] `--verify` validates the hash chain without filters
- [ ] Missing DB → clear error message, exit 1
- [ ] No matches → empty output, exit 0
- [ ] `arguments` is a proper JSON object in output, not double-encoded
- [ ] All 13 tests pass
- [ ] No writes to the database from the `logs` command

## 6. What This Does NOT Include

- Pretty-printing / table formatting (JSON lines only)
- `--format` option (no CSV, no table, no YAML)
- `--since` / `--until` time range filters (could add later, not needed for MVP)
- Streaming / follow mode (`--follow` like `tail -f`)
- Pagination
- Any interaction with a running proxy

## 7. Definition of Done

1. `logs` stub in `cli.py` replaced with working implementation
2. `verify_chain` extracted as module-level function in `audit.py` (takes `db_path`)
3. 13 tests in `tests/test_cli_logs.py` passing
4. `CLAUDE.md` updated: `cli.py` entry updated from "logs (stub)" to implemented, test file listed
5. `ISSUE_TRACKER.md` updated: #13 marked ✅ Done