# Issue #12: SQLite Audit Writer — Implementation Spec

**Status:** Ready to build  
**Depends on:** Nothing (can be built in isolation)  
**Blocked by this:** #13 (`agentgate logs` CLI), #15 (acceptance tests)  
**Estimated effort:** 3–4 hours  

---

## 1. What This Is

A background-thread SQLite writer that records every tool-call decision (allow/block) to an append-only, hash-chained audit log. The proxy's decision path calls `writer.log(...)` which enqueues and returns immediately. A daemon thread drains the queue and writes to SQLite sequentially.

This is the tamper-evidence layer. Each row's `entry_hash` covers its own contents plus the previous row's hash, forming a chain. If any row is modified or deleted after the fact, the chain breaks and verification fails.

---

## 2. Public API

### `AuditWriter` class

```python
# src/agentgate/audit.py

class AuditWriter:
    """Append-only SQLite audit writer with SHA-256 hash chaining.
    
    Thread-safe: the public log() method enqueues and returns immediately.
    SQLite connection lives exclusively in the background thread.
    """

    def __init__(self, db_path: str | Path = "agentgate_audit.db") -> None:
        """Create the audit_log table if needed, start the background thread."""

    def log(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Literal["allow", "block"],
        matched_rule: str | None = None,
        matched_detector: str | None = None,
        message: str | None = None,
    ) -> None:
        """Enqueue an audit entry. Non-blocking. Returns immediately.
        
        Arguments dict is serialized to JSON string internally.
        Timestamp is captured at call time (not dequeue time).
        """

    def close(self, timeout: float = 2.0) -> None:
        """Flush remaining entries and stop the background thread.
        
        Blocks up to `timeout` seconds waiting for the queue to drain.
        Safe to call multiple times.
        """

    def verify_chain(self) -> tuple[bool, int]:
        """Walk the full audit log and verify hash chain integrity.
        
        Returns (is_valid, row_count). Used by tests and `agentgate logs --verify`.
        This is a read operation — runs on the caller's thread, opens its own
        read-only SQLite connection.
        """
```

### What `log()` does NOT accept

- No `AuditEntry` Pydantic model as input. The caller passes primitives. The writer handles timestamping, JSON serialization, and hashing internally. This keeps the call site in `proxy.py` minimal.
- No `prev_hash` or `entry_hash` — these are computed by the writer, not the caller.

### Why not accept `AuditEntry` directly?

The `AuditEntry` model has `prev_hash` and `entry_hash` fields that only the writer can compute (they depend on the previous row). Requiring the caller to construct a full `AuditEntry` would force hash computation into the proxy's hot path. Instead, the writer accepts raw fields, timestamps at enqueue time, and computes hashes in the background thread.

---

## 3. SQLite Schema

Matches Spec Section 8 exactly:

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,   -- ISO 8601 UTC
    session_id       TEXT    NOT NULL,
    tool_name        TEXT    NOT NULL,
    arguments        TEXT    NOT NULL,   -- JSON string
    decision         TEXT    NOT NULL,   -- "allow" | "block"
    matched_rule     TEXT,               -- rule name or NULL
    matched_detector TEXT,               -- detector name or NULL
    message          TEXT,               -- block reason or NULL
    prev_hash        TEXT    NOT NULL,   -- SHA-256 hex or "genesis"
    entry_hash       TEXT    NOT NULL    -- SHA-256 hex
);
```

No indexes beyond the implicit `id` primary key. The table is append-only and small (hundreds to low thousands of rows per session). Full-table scans for `agentgate logs` filtering are fine at this scale.

---

## 4. Hash Chain Algorithm

```
entry_hash = SHA-256(prev_hash + "|" + timestamp + "|" + tool_name + "|" + arguments_json + "|" + decision)
```

- `prev_hash` for the first entry is the literal string `"genesis"`.
- All subsequent entries use the `entry_hash` of the immediately preceding row.
- The pipe `|` delimiter prevents field-boundary ambiguity.
- `arguments_json` is the compact JSON serialization (`json.dumps(arguments, separators=(',', ':'), sort_keys=True)`) — sorted keys ensure deterministic hashing regardless of dict insertion order.
- `timestamp` is ISO 8601 UTC with microsecond precision: `datetime.now(timezone.utc).isoformat()`.

### Why sort_keys=True?

Python dicts preserve insertion order, but the same logical arguments could arrive in different key orders across framework versions. Sorting keys makes the hash deterministic for the same logical content.

### Verification algorithm

```python
def verify_chain(self) -> tuple[bool, int]:
    """Returns (is_valid, total_rows)."""
    # Open read-only connection in caller thread
    conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT prev_hash, timestamp, tool_name, arguments, decision, entry_hash "
        "FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()

    expected_prev = "genesis"
    for prev_hash, ts, tool, args, decision, entry_hash in rows:
        if prev_hash != expected_prev:
            return (False, len(rows))
        recomputed = _compute_hash(prev_hash, ts, tool, args, decision)
        if recomputed != entry_hash:
            return (False, len(rows))
        expected_prev = entry_hash
    return (True, len(rows))
```

---

## 5. Threading Model

```
Proxy decision path (main thread / asyncio event loop)
    │
    │  writer.log(session_id, tool_name, ...)
    │    → captures timestamp
    │    → serializes arguments to JSON
    │    → queue.put_nowait(_QueueEntry(...))
    │    → returns immediately
    │
    ▼
queue.Queue (unbounded)
    │
    ▼
Background daemon thread (_writer_loop)
    │  Owns the sole sqlite3.Connection
    │  Loops: entry = queue.get()
    │    → compute hash (needs prev_hash state)
    │    → INSERT INTO audit_log
    │    → conn.commit()  (one commit per entry)
    │    → update prev_hash in memory
    │    → queue.task_done()
    │
    │  Sentinel: receives _SHUTDOWN → breaks loop → conn.close()
```

### Key design decisions

1. **Unbounded queue.** Audit writes are cheap and infrequent (one per tool call, tool calls take 500ms–10s due to LLM inference). The queue will never grow meaningfully. Bounded queues risk blocking the proxy's decision path, which is the one thing we must not do.

2. **One commit per entry.** Simpler than batching. At single-agent workloads (the MVP target), we're doing maybe 1–5 writes/second. SQLite handles this trivially. Batching is a premature optimization that complicates shutdown flushing.

3. **Daemon thread.** If the proxy crashes without calling `close()`, the thread dies automatically. We may lose the last queued entry. Acceptable for MVP — the proxy isn't a financial ledger.

4. **`prev_hash` tracked in memory.** The background thread keeps the last `entry_hash` as instance state. On init, it reads the last row's `entry_hash` from SQLite (or uses `"genesis"` if the table is empty). This means the writer can resume appending to an existing audit log across proxy restarts.

5. **SQLite connection in background thread only.** SQLite's threading model (`check_same_thread=True` by default) enforces this. `verify_chain()` opens a separate read-only connection on the caller's thread — this is safe because SQLite supports concurrent readers.

### Internal queue entry

```python
@dataclass(frozen=True)
class _QueueEntry:
    timestamp: str          # ISO 8601 UTC, captured at enqueue time
    session_id: str
    tool_name: str
    arguments_json: str     # pre-serialized, sorted keys
    decision: str           # "allow" | "block"
    matched_rule: str | None
    matched_detector: str | None
    message: str | None
```

Using a frozen dataclass (not Pydantic) for the internal queue entry. This is a private implementation detail — no validation needed, and dataclass construction is faster.

### Shutdown sentinel

```python
_SHUTDOWN = object()  # module-level sentinel
```

`close()` calls `queue.put(_SHUTDOWN)`, then `thread.join(timeout)`. The background thread checks `if entry is _SHUTDOWN: break`.

---

## 6. Integration Point: proxy.py

The `AuditWriter` will be instantiated in `StdioProxy.__init__` and called from `_intercepting_relay` (for policy-evaluated calls) and `_relay` (for passthrough mode, if we want to log allowed calls in passthrough mode — decision below).

### What gets logged

| Scenario | Logged? | decision |
|----------|---------|----------|
| `tools/call` evaluated by policy, allowed | Yes | `"allow"` |
| `tools/call` evaluated by policy, blocked | Yes | `"block"` |
| `tools/call` in passthrough mode (no policy) | No | — |
| Non-`tools/call` messages (initialize, tools/list, etc.) | No | — |

**Rationale:** In passthrough mode there's no policy to evaluate, so logging "allow" for everything adds noise with zero signal. The audit log is meaningful only when a policy is loaded. This also means we don't need to thread the `AuditWriter` through `_relay` — only `_intercepting_relay` calls it.

### Call site in `_intercepting_relay`

```python
# After decision = evaluate(parsed.tool_call, policy):
if audit_writer is not None:
    audit_writer.log(
        session_id=session_id,
        tool_name=parsed.tool_call.tool_name,
        arguments=parsed.tool_call.arguments,
        decision=decision.action,
        matched_rule=decision.matched_rule,
        matched_detector=decision.matched_detector,
        message=decision.message,
    )
```

The `session_id` is a UUID generated once per `StdioProxy.run()` invocation. Pass it into `_intercepting_relay` as a parameter.

### Wiring changes to proxy.py

1. `StdioProxy.__init__` accepts optional `audit_db: str | Path | None = None`. If a policy is loaded, create an `AuditWriter`. If `audit_db` is None and policy exists, default to `"agentgate_audit.db"` in the current directory.
2. `_intercepting_relay` signature gains `audit_writer: AuditWriter | None` and `session_id: str` parameters.
3. `StdioProxy.run()` generates `session_id = str(uuid.uuid4())` at the top.
4. `StdioProxy.run()` calls `audit_writer.close()` in the shutdown sequence (after child process cleanup).

### CLI wiring (cli.py)

Add `--audit-db` option to the `start` command. Default: `"agentgate_audit.db"`. Pass through to `StdioProxy`. This is a one-line addition.

---

## 7. File Structure

One file: `src/agentgate/audit.py`. Everything lives here — the class, the hash function, the schema, the internal queue entry dataclass.

No new dependencies. Uses only stdlib: `sqlite3`, `threading`, `queue`, `hashlib`, `json`, `datetime`, `dataclasses`, `pathlib`.

---

## 8. Test Plan

All tests in `tests/test_audit.py`. All sync, all use `tmp_path` for the SQLite file. No asyncio.

### Unit tests (AuditWriter in isolation)

| # | Test | What it proves |
|---|------|----------------|
| 1 | `test_creates_table` | Constructor creates `audit_log` table in a fresh DB. |
| 2 | `test_log_and_read_back` | Write one entry via `log()`, read it back, verify all fields present and correct. |
| 3 | `test_genesis_hash` | First entry has `prev_hash = "genesis"`. |
| 4 | `test_hash_chain_two_entries` | Second entry's `prev_hash` equals first entry's `entry_hash`. |
| 5 | `test_hash_determinism` | Same inputs produce the same `entry_hash` across two separate writer instances. |
| 6 | `test_verify_chain_valid` | `verify_chain()` returns `(True, N)` for a valid log. |
| 7 | `test_verify_chain_tampered` | Manually UPDATE one row's `arguments` field, `verify_chain()` returns `(False, N)`. |
| 8 | `test_verify_chain_empty` | `verify_chain()` on empty table returns `(True, 0)`. |
| 9 | `test_close_flushes` | Enqueue 10 entries, call `close()`, verify all 10 are in the DB. |
| 10 | `test_close_idempotent` | Calling `close()` twice doesn't raise. |
| 11 | `test_resume_existing_db` | Create writer, log 3 entries, close. Create new writer on same DB, log 1 more. Verify chain of 4 is valid. |
| 12 | `test_timestamp_is_enqueue_time` | Verify the timestamp is captured at `log()` call time, not at write time (inject a small delay and check). |
| 13 | `test_arguments_sorted_keys` | Log with `{"b": 2, "a": 1}`, read back `arguments` field, verify it's `{"a":1,"b":2}`. |
| 14 | `test_concurrent_writes` | Spawn 5 threads each logging 10 entries, verify all 50 are in the DB with a valid chain. |

### Performance test

| # | Test | What it proves |
|---|------|----------------|
| 15 | `test_log_latency_under_2ms` | Time 100 `log()` calls, assert p99 < 2ms. This is the enqueue latency, not the write latency. Should be well under 1ms. |

**Total: 15 tests.**

---

## 9. Acceptance Criteria

1. `AuditWriter.log()` returns in < 2ms (p99) as measured by `test_log_latency_under_2ms`. This satisfies Spec Section 2 P2.
2. Hash chain is tamper-evident: modifying any row's content causes `verify_chain()` to return `False`.
3. First entry uses `"genesis"` as `prev_hash`.
4. Writer can resume appending to an existing DB file (supports proxy restarts).
5. `close()` flushes all queued entries before returning.
6. No cross-thread SQLite connection sharing.
7. All 15 tests pass.

---

## 10. What This Does NOT Include

- **`agentgate logs` CLI command** — that's Issue #13. It reads from the same SQLite file but is a separate concern.
- **`--verify` flag** — deferred to #13. `verify_chain()` is exposed as a method for #13 to call.
- **Encryption at rest** — explicitly out of scope per spec.
- **Ed25519 signatures** — v1 feature, not MVP.
- **Log rotation or size limits** — not needed for MVP workloads.
- **Async/await** — deliberately avoided. Background thread + queue is simpler and doesn't infect the codebase.
- **Batch commits** — one commit per entry is correct for MVP throughput.

---

## 11. Risks

### Risk 1: SQLite write contention under concurrent proxy instances

**Likelihood:** Low for MVP (single proxy instance).  
**Impact:** Writes block on SQLite's file lock, queue backs up, `close()` timeout hit.  
**Mitigation:** Not a problem for MVP (single agent ↔ single MCP server). If it becomes a problem in v1, switch to WAL mode (`PRAGMA journal_mode=WAL`) which allows concurrent readers + one writer. Can add this pragma in `__init__` with zero API change. Not adding it now to avoid unnecessary complexity.

### Risk 2: Lost entries on hard crash

**Likelihood:** Medium (crashes happen).  
**Impact:** Last 1–2 entries may be lost if the daemon thread hasn't drained the queue.  
**Mitigation:** Acceptable for MVP. The audit log is evidence, not a transaction journal. One missing entry at the tail of a crash doesn't break the security story. If this matters in v1, add `fsync` after each commit.

### Risk 3: `arguments_json` serialization edge cases

**Likelihood:** Low.  
**Impact:** Non-JSON-serializable values in arguments would crash the background thread.  
**Mitigation:** Use `json.dumps(arguments, separators=(',',':'), sort_keys=True, default=str)` — the `default=str` fallback converts any non-serializable value to its string representation. This is a safety net, not a feature.

---

## 12. Implementation Order

1. Write the `_compute_hash()` function and test it in isolation (verify determinism).
2. Write `AuditWriter.__init__` — create table, read last hash, start thread.
3. Write `AuditWriter.log()` — timestamp, serialize, enqueue.
4. Write `_writer_loop()` — dequeue, hash, INSERT, commit.
5. Write `AuditWriter.close()` — sentinel, join.
6. Write `AuditWriter.verify_chain()` — read-only verification.
7. Write all 15 tests.
8. Wire into `proxy.py` and `cli.py` (add `audit_writer` param, session_id generation, close on shutdown, `--audit-db` CLI option).

Steps 1–7 can be done without touching any other file. Step 8 is the integration step and is small.