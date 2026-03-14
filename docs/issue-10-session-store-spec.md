# Issue #10: Session Store — Implementation Spec

**Status:** Ready to build  
**Depends on:** #5 (proxy wiring) ✅  
**Blocks:** #11 (chain detection), #15 (acceptance tests AT-3)  
**Estimated effort:** ~2 hours code + tests  

---

## 1. What This Is

A minimal in-memory sliding window that records recent tool calls and their responses within a single proxy session. Its sole consumer is chain detection (#11), which needs to answer: "Did tool A return sensitive data recently, and is tool B now being called?"

This is plumbing. Keep it simple.

## 2. What This Is NOT

- Not persistent across sessions (no DB, no file)
- Not shared across proxy instances
- Not a general event bus or observable stream
- Not responsible for any policy logic — it stores; chain detection queries

## 3. Data Model

One dataclass. No Pydantic — this is internal hot-path data, not a serialization boundary.

```python
@dataclass(frozen=True, slots=True)
class SessionEntry:
    tool_name: str
    arguments: dict[str, Any]
    response_text: str | None   # None until response arrives
    timestamp: float            # time.monotonic() — not wall clock, just ordering/recency
```

**Why `frozen=True`:** Entries are append-only facts. Nothing mutates them after creation.

**Why `response_text: str | None`:** The proxy intercepts the *request* first (when it decides allow/block). The *response* comes back later from the MCP server. The session store must support a two-phase write:

1. **On allow decision:** Create entry with `response_text=None`, append to deque, return the index/ref.
2. **On response received:** Update the most recent entry's `response_text`.

This means `frozen=True` won't work for in-place mutation. Two options:

- **Option A:** Use a mutable dataclass (drop `frozen`). Simpler.
- **Option B:** Store entries as `(request_entry, response_text)` tuples in the deque, replacing the tuple on response. Purer but fiddly.

**Decision: Option A.** Drop `frozen`. This is internal state, not a public API. Purity isn't worth the complexity.

```python
@dataclass(slots=True)
class SessionEntry:
    tool_name: str
    arguments: dict[str, Any]
    response_text: str | None = None
    timestamp: float = 0.0
```

## 4. SessionStore Class

```python
class SessionStore:
    """Sliding window of recent tool calls for chain detection."""

    def __init__(self, max_size: int = 50) -> None:
        self._entries: deque[SessionEntry] = deque(maxlen=max_size)

    def record_request(self, tool_name: str, arguments: dict[str, Any]) -> SessionEntry:
        """Record an allowed tool call. Returns the entry (response_text=None)."""

    def record_response(self, entry: SessionEntry, response_text: str) -> None:
        """Attach response text to a previously recorded entry."""

    def recent(self, n: int | None = None) -> list[SessionEntry]:
        """Return the last N entries (or all if n is None). Most recent last."""

    def clear(self) -> None:
        """Clear all entries. Called on proxy shutdown."""

    def __len__(self) -> int:
        return len(self._entries)
```

### Design decisions

**`max_size=50` default.** The chain rule `window` field (default 10, per spec) controls how far back chain detection looks. The session store should hold more than the largest plausible window so that multiple chain rules with different window sizes can coexist. 50 is generous. This is not user-configurable in MVP — hardcoded default, overridable via constructor arg for testing.

**`record_request` returns the entry.** The proxy holds the reference and calls `record_response` on it when the MCP server responds. This avoids index-based lookup, which is fragile if entries are evicted between request and response.

**`recent()` returns a list copy.** Chain detection iterates over it. No mutation of the deque during iteration.

**No locking.** The proxy is single-threaded async (one event loop, one `_intercepting_relay` coroutine handles agent→server, one `_relay` handles server→agent). Requests and responses alternate naturally — there's no concurrent mutation risk. If this assumption breaks later (multi-agent), add a lock then.

## 5. Integration Points

### 5.1 Proxy (`proxy.py`)

The `StdioProxy` creates one `SessionStore` instance per `run()` invocation. It's passed to `_intercepting_relay` (agent→server direction) and to a new response-intercepting relay (server→agent direction).

**Current state:** The server→agent relay is a plain `_relay` (pass-through). To capture responses, it needs to become response-aware.

**Change 1: `StdioProxy.__init__`**
```python
self.session = SessionStore()
```

**Change 2: `_intercepting_relay` (agent→server)**

After an `allow` decision for a `tool_call`, before forwarding:
```python
entry = self.session.record_request(tool_call.tool_name, tool_call.arguments)
# Stash entry keyed by request_id so response relay can find it
self._pending_responses[parsed.request_id] = entry
```

**Change 3: New `_response_intercepting_relay` (server→agent)**

Replace the plain `_relay` for server→agent with a version that:
1. Reads each message from the MCP server
2. Parses it as JSON
3. If it's a JSON-RPC response (has `id` + `result`) and the `id` is in `_pending_responses`:
   - Extract `result` as string (JSON-serialize it if it's a dict/list, or use raw text)
   - Call `entry.record_response(entry, result_text)`
   - Remove from `_pending_responses`
4. Forward the original bytes to the agent (zero modification)

**Why intercept responses at all?** Chain detection needs to know what tool A *returned* (e.g., did it contain `PRIVATE KEY`?). Without response capture, chain rules are blind.

**`_pending_responses` dict:** `dict[str | int, SessionEntry]` — maps JSON-RPC request ID to the session entry awaiting its response. Entries are removed on response receipt or on session clear.

### 5.2 Engine (`engine.py`)

**Not changed in this issue.** The engine's Step 5 (chain_rule) will receive the `SessionStore` in Issue #11. This issue only builds the store and wires it into the proxy's read/write path.

The engine signature will change in #11 to:
```python
def evaluate(tool_call: ToolCall, policy: CompiledPolicy, session: SessionStore | None = None) -> Decision
```

But that's #11's problem, not #10's.

### 5.3 Chain detector (`detectors/chain.py`)

**Not changed in this issue.** Chain detection (#11) will query `session.recent(window)` and match against `ChainRule.steps`. This issue just ensures the data is there.

## 6. What Gets Stored as `response_text`

MCP `tools/call` responses follow JSON-RPC format:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {"type": "text", "text": "file contents here..."}
    ]
  }
}
```

**What to store:** JSON-serialize `result` as a string. Chain detection will regex-match against this string. This is simple and correct — if the response contains `PRIVATE KEY` anywhere in the result payload, the regex will find it regardless of nesting.

**Edge cases:**
- If `result` is missing (error response): store nothing (`response_text` stays `None`). Error responses don't contribute to chain context.
- If `result` is very large: store it anyway. The deque has a max size, so memory is bounded by `max_size * max_response_size`. For MVP with single-agent workloads, this is fine. If it becomes a problem, truncate to 64KB in v1.

## 7. File: `src/agentgate/session.py`

```
session.py
├── SessionEntry (dataclass)
├── SessionStore
│   ├── __init__(max_size=50)
│   ├── record_request(tool_name, arguments) -> SessionEntry
│   ├── record_response(entry, response_text) -> None
│   ├── recent(n=None) -> list[SessionEntry]
│   ├── clear() -> None
│   └── __len__() -> int
```

~50 lines of implementation. No dependencies beyond stdlib (`collections.deque`, `time`, `dataclasses`).

## 8. Tests: `tests/test_session.py`

All sync, no I/O. Target: ~12 tests.

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_empty_store` | New store has len 0, `recent()` returns `[]` |
| 2 | `test_record_request` | Entry appended, `tool_name` and `arguments` correct, `response_text` is None |
| 3 | `test_record_response` | After `record_response`, entry's `response_text` is set |
| 4 | `test_recent_ordering` | Entries returned in insertion order (oldest first, most recent last) |
| 5 | `test_recent_n` | `recent(3)` returns last 3 entries from a store with 5 |
| 6 | `test_recent_n_larger_than_store` | `recent(100)` on a 3-entry store returns all 3 |
| 7 | `test_max_size_eviction` | Store with `max_size=3` evicts oldest entry when 4th is added |
| 8 | `test_clear` | After `clear()`, len is 0 and `recent()` is empty |
| 9 | `test_timestamp_monotonic` | Timestamps are non-decreasing across entries |
| 10 | `test_response_after_eviction` | Recording a response on an evicted entry doesn't crash (no-op or still works on the object) |
| 11 | `test_record_request_returns_entry` | Return value is a `SessionEntry` with correct fields |
| 12 | `test_default_max_size` | Default `max_size` is 50 |

## 9. Proxy Integration Tests

These go in existing `tests/test_proxy_policy.py` or a new `tests/test_proxy_session.py`. They require the echo MCP server and are async integration tests.

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_session_records_allowed_call` | After allowing a tool call, `proxy.session` has 1 entry with correct tool_name |
| 2 | `test_session_skips_blocked_call` | After blocking a tool call, `proxy.session` has 0 entries |
| 3 | `test_session_captures_response` | After a full round-trip (allow + response), entry has `response_text` populated |

**Note:** These proxy-level integration tests are stretch. If they're fiddly to wire (need to inspect proxy internals mid-run), defer them to #11 where chain detection provides an end-to-end observable. The unit tests on `SessionStore` are the priority.

## 10. Acceptance Criteria

1. `SessionStore` class exists in `src/agentgate/session.py`
2. All 12 unit tests pass
3. `StdioProxy` creates a `SessionStore` and wires it into the relay path
4. Allowed tool calls are recorded (request side)
5. Responses from MCP server are captured and attached to the correct entry
6. Blocked tool calls are NOT recorded in the session store
7. Session store is cleared on proxy shutdown (deque goes out of scope — implicit, but verify no leaks)

## 11. Scope Boundary

**In scope:**
- `SessionStore` class with deque
- `SessionEntry` dataclass
- Proxy integration (create store, record on allow, capture response)
- `_pending_responses` dict for request-to-response correlation
- Unit tests for session store

**Out of scope (deferred to #11):**
- Chain detection logic
- Engine receiving session store
- Any policy evaluation that uses session history
- Configurable `max_size` from policy YAML

## 12. Risk

**Risk:** Response interception in the server→agent relay adds complexity to a working code path. If the JSON parsing is wrong or the request ID correlation fails, responses could be silently dropped or the proxy could crash.

**De-risk:** The response relay modification must be minimal. Parse JSON, check for `id` in `_pending_responses`, extract `result`, move on. If JSON parsing fails, log a warning and forward the raw bytes unchanged — never break the relay for session bookkeeping. The session store is best-effort for chain detection, not a critical path component.

```python
# Pseudocode for response interception — fail-safe
try:
    msg = json.loads(payload)
    req_id = msg.get("id")
    if req_id is not None and req_id in self._pending_responses:
        entry = self._pending_responses.pop(req_id)
        result = msg.get("result")
        if result is not None:
            self.session.record_response(entry, json.dumps(result))
except Exception:
    log.debug("Failed to parse response for session tracking, skipping")
# Always forward regardless
await write_message(agent_writer, payload)
```

This pattern ensures the proxy never breaks even if session bookkeeping fails.