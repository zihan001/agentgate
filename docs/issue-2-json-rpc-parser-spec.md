# Issue #2: Implement JSON-RPC Message Parser

**Status:** Implementation-ready
**Milestone:** PR1 — First End-to-End Interception
**Depends on:** #1 (stdio passthrough proxy — COMPLETE)
**Blocks:** #5 (end-to-end wiring)
**Target file:** `src/agentgate/parser.py`
**Test file:** `tests/test_parser.py`
**Estimated effort:** 2–3 hours
**Ref:** MVP Spec Section 8 (Request Parser component)

---

## 1. Objective

Parse raw `bytes` payloads returned by `read_message()` into structured objects. For `tools/call` requests, produce a `ToolCall` model instance with `tool_name`, `arguments`, and `call_id`. For everything else, return a passthrough marker so the proxy relay loop knows not to intercept.

This is the parsing boundary. Issue #1 solved the I/O boundary (LSP framing). This issue sits between I/O and policy evaluation. It is a pure function — bytes in, structured data out. No I/O, no async, no side effects.

---

## 2. Scope

### In scope

- `ParsedMessage` Pydantic model in `src/agentgate/parser.py`
- `parse_message(payload: bytes) -> ParsedMessage` function
- `build_error_response(request_id, code, message) -> bytes` helper
- Classification of all JSON-RPC message types (tool_call, request, notification, response, invalid)
- Extraction of `tool_name` and `arguments` from `tools/call` params into `ToolCall`
- 12 unit tests covering all message types and edge cases

### Out of scope

- Any I/O — reading/writing from streams is `proxy.py`
- Policy evaluation — Issue #4
- Detector execution — PR2
- Modifying or rewriting messages
- Batched JSON-RPC — MCP does not use it
- Newline-delimited JSON framing — Issue #1 confirmed MCP uses Content-Length LSP framing exclusively; framing is fully handled by `read_message()` already

---

## 3. Technical Decisions

### Decision 1: Parser is a pure synchronous function

**Choice:** `parse_message(payload: bytes) -> ParsedMessage` is sync, stateless, no side effects.

**Rationale:** The proxy calls `read_message()` (async, returns `bytes`), then calls `parse_message()` (sync, returns structured data), then decides what to do. Keeping parsing sync means it can be called from anywhere, tested trivially, and never introduces concurrency bugs. The proxy already handles async I/O — the parser must not.

### Decision 2: Discriminated result type, not exceptions

**Choice:** Return a `ParsedMessage` with a `kind` field that classifies the message. Do not raise exceptions for non-`tools/call` messages.

**Rationale:** Most messages flowing through the proxy are NOT `tools/call` — they are `initialize`, `initialized`, `tools/list`, responses, notifications. These are the common case and must be passed through without touching. Exceptions for normal control flow are wrong. The proxy relay loop will check `parsed.kind == "tool_call"` and only route to the engine in that case. Everything else gets forwarded as raw bytes.

### Decision 3: Malformed JSON returns an error kind, not an exception

**Choice:** If `payload` is not valid JSON or not a valid JSON-RPC message, return `ParsedMessage(kind="invalid", ...)` with the raw bytes preserved.

**Rationale:** The proxy must decide what to do with malformed messages — most likely forward them so the MCP server can return its own error. Raising an exception would force the relay loop into error handling for something that is not the proxy's problem. Let the proxy decide.

### Decision 4: `ToolCall.call_id` gets the JSON-RPC `id`

**Choice:** Map the JSON-RPC `id` field to `ToolCall.call_id`.

**Rationale:** When the engine blocks a call, the proxy needs to send a JSON-RPC error response with the matching `id`. The `ToolCall` model already has `call_id: str | int | None`. Populate it from the request's `id` field.

### Decision 5: No dependency on `proxy.py`

**Choice:** `parser.py` imports only from `models.py` and stdlib `json`.

**Rationale:** No circular dependencies. Parser is a leaf module. Proxy depends on parser, never the reverse.

---

## 4. Data Model

### `ParsedMessage`

```python
class ParsedMessage(BaseModel):
    """Result of parsing a raw JSON-RPC payload."""

    kind: Literal["tool_call", "request", "notification", "response", "invalid"]
    raw: bytes                          # Original payload — always preserved for passthrough
    tool_call: ToolCall | None = None   # Populated only when kind == "tool_call"
    request_id: str | int | None = None # JSON-RPC id (requests + responses), None for notifications
    method: str | None = None           # JSON-RPC method (requests + notifications)

    model_config = ConfigDict(arbitrary_types_allowed=True)
```

### Kind classification logic

| Condition | Kind |
|-----------|------|
| Has `method` == `"tools/call"` and has `id` | `tool_call` |
| Has `method` and has `id` (any other method) | `request` |
| Has `method` but no `id` | `notification` |
| Has `result` or `error` but no `method` | `response` |
| JSON parse failure or missing required fields | `invalid` |

### Where `ToolCall` fields come from

MCP `tools/call` request structure:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {"path": "/etc/passwd"}
  }
}
```

Field mapping:

| ToolCall field | Source |
|----------------|--------|
| `tool_name` | `params.name` |
| `arguments` | `params.arguments` (default `{}` if absent) |
| `call_id` | `id` |

---

## 5. Implementation

### `parse_message(payload: bytes) -> ParsedMessage`

```
1. Try json.loads(payload). On JSONDecodeError → return ParsedMessage(kind="invalid", raw=payload)
2. If result is not a dict → return ParsedMessage(kind="invalid", raw=payload)
3. Extract id = msg.get("id")
4. Extract method = msg.get("method")
5. If method is None:
   a. If "result" in msg or "error" in msg → kind="response", request_id=id
   b. Else → kind="invalid"
6. If method is not None and id is None → kind="notification", method=method
7. If method == "tools/call" and id is not None:
   a. params = msg.get("params", {})
   b. tool_name = params.get("name")
   c. arguments = params.get("arguments", {})
   d. If tool_name is None → kind="invalid" (malformed tools/call — cannot evaluate without tool name)
   e. Else → kind="tool_call", tool_call=ToolCall(tool_name, arguments, call_id=id)
8. If method is not None and id is not None and method != "tools/call" → kind="request"
```

This is ~30 lines of code. No cleverness needed.

### `build_error_response(request_id: str | int, code: int, message: str) -> bytes`

```python
def build_error_response(request_id: str | int, code: int, message: str) -> bytes:
    """Build a JSON-RPC error response payload as bytes (not LSP-framed).

    The caller wraps this with write_message() which adds Content-Length framing.
    """
    return json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }).encode()
```

Use JSON-RPC error code `-32600` (Invalid Request) for policy blocks. MCP does not define a custom error code for "blocked by policy" and `-32600` is the standard "server refused to process" code.

---

## 6. How This Integrates with the Proxy (Issue #5 Preview)

The Issue #5 relay loop will change from the current opaque relay to:

```
payload = await read_message(reader)       # Issue #1 — bytes
parsed = parse_message(payload)            # Issue #2 — structured
if parsed.kind == "tool_call":
    decision = engine.evaluate(parsed.tool_call)  # Issue #4
    if decision.action == "block":
        error = build_error_response(        # Issue #2
            parsed.request_id, -32600, decision.message
        )
        await write_message(agent_writer, error)
        continue
await write_message(server_writer, parsed.raw)  # passthrough original bytes
```

Key contract: `parsed.raw` is always the original bytes. Non-`tool_call` messages are forwarded using `parsed.raw` with zero re-serialization.

---

## 7. Test Plan

**File:** `tests/test_parser.py`

All tests are synchronous. No fixtures, no subprocess, no I/O. Pure function testing.

### Test 1: `test_parse_tools_call`

**Input:** Valid `tools/call` JSON-RPC request (`read_file`, `path="/etc/passwd"`, id=3)
**Assert:** `kind == "tool_call"`, `tool_call.tool_name == "read_file"`, `tool_call.arguments == {"path": "/etc/passwd"}`, `tool_call.call_id == 3`, `method == "tools/call"`, `raw` preserved

### Test 2: `test_parse_tools_call_empty_arguments`

**Input:** `tools/call` where `params` has `name` but no `arguments` key
**Assert:** `kind == "tool_call"`, `tool_call.arguments == {}`

### Test 3: `test_parse_initialize_request`

**Input:** `initialize` request with `id=1`
**Assert:** `kind == "request"`, `method == "initialize"`, `request_id == 1`, `tool_call is None`

### Test 4: `test_parse_tools_list_request`

**Input:** `tools/list` request with `id=2`
**Assert:** `kind == "request"`, `method == "tools/list"`, `request_id == 2`

### Test 5: `test_parse_initialized_notification`

**Input:** `{"jsonrpc": "2.0", "method": "initialized"}` — no `id`
**Assert:** `kind == "notification"`, `method == "initialized"`, `request_id is None`

### Test 6: `test_parse_response_with_result`

**Input:** `{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}`
**Assert:** `kind == "response"`, `request_id == 1`, `method is None`

### Test 7: `test_parse_error_response`

**Input:** `{"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}`
**Assert:** `kind == "response"`, `request_id == 1`

### Test 8: `test_parse_invalid_json`

**Input:** `b"not json at all"`
**Assert:** `kind == "invalid"`, `raw == b"not json at all"`, no exception raised

### Test 9: `test_parse_json_not_object`

**Input:** `b"[1, 2, 3]"` — valid JSON, not an object
**Assert:** `kind == "invalid"`

### Test 10: `test_parse_tools_call_missing_name`

**Input:** `tools/call` request where `params` exists but has no `name` field
**Assert:** `kind == "invalid"`

### Test 11: `test_build_error_response`

**Call:** `build_error_response(3, -32600, "Blocked by policy")`
**Assert:** JSON-decoded result has `id == 3`, `error.code == -32600`, `error.message == "Blocked by policy"`, `jsonrpc == "2.0"`. Result is `bytes`.

### Test 12: `test_raw_bytes_preserved_for_all_kinds`

**Input:** One payload per kind (`tool_call`, `request`, `notification`, `response`, `invalid`)
**Assert:** For each, `parsed.raw` is byte-identical to the input. This guarantees passthrough forwarding can use the original bytes without re-serialization.

---

## 8. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | `tools/call` requests produce a `ToolCall` with correct `tool_name`, `arguments`, `call_id` | Tests 1, 2 |
| AC-2 | Non-`tools/call` requests, notifications, and responses are classified correctly without producing a `ToolCall` | Tests 3–7 |
| AC-3 | Malformed payloads (bad JSON, non-object, missing tool name) return `kind="invalid"` without raising exceptions | Tests 8–10 |
| AC-4 | `build_error_response` produces a valid JSON-RPC error as bytes | Test 11 |
| AC-5 | Original raw bytes are always preserved on `ParsedMessage` for zero-cost passthrough | Test 12 |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| MCP `tools/call` params structure differs from assumed `{name, arguments}` | Low | Medium | Echo server in Issue #1 tests already uses this structure. Real MCP servers confirmed via Issue #1 empirical validation. If a server deviates, integration tests in Issue #7 will catch it. |
| Large payloads cause JSON parse slowness | Very Low | Low | `json.loads` on 1MB is ~10ms. Tool call arguments are never that large in practice. Not a real risk. |
| Notification vs request ambiguity | None | None | JSON-RPC 2.0 spec is unambiguous: presence of `id` distinguishes request from notification. |
| `params` field absent on `tools/call` | Low | Low | Handled: `msg.get("params", {})` defaults to empty dict. Missing `name` inside triggers `kind="invalid"`. |

---

## 10. Design Constraints for Downstream Issues

1. **`ParsedMessage.raw` is the passthrough primitive.** Issue #5 forwards non-`tools/call` messages by calling `write_message(writer, parsed.raw)`. No re-serialization. This preserves byte-level correctness and avoids subtle JSON formatting changes.

2. **`ParsedMessage` is the input to the engine.** Issue #5 relay loop extracts `parsed.tool_call` and passes it to `engine.evaluate()`. The engine never sees raw bytes — only the structured `ToolCall`.

3. **`build_error_response` returns unframed bytes.** The caller wraps it with `write_message()` which adds Content-Length framing. Do not double-frame.

4. **Parser has zero dependency on `proxy.py`.** Import chain: `proxy.py` → `parser.py` → `models.py`. No reverse dependency. No circular imports.

5. **`kind="invalid"` means "forward it anyway."** The proxy should not silently drop malformed messages. The MCP server can decide how to handle them. The parser's job is classification, not enforcement.

---

## 11. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/parser.py` | **Replace stub** | `ParsedMessage` model, `parse_message()`, `build_error_response()` |
| `tests/test_parser.py` | **New** | 12 unit tests, all synchronous |

No other files are touched. `proxy.py`, `engine.py`, `policy.py` are unchanged.

---

## 12. Definition of Done

- [ ] `src/agentgate/parser.py` contains `ParsedMessage`, `parse_message()`, `build_error_response()`
- [ ] `parse_message` correctly classifies all 5 message kinds (`tool_call`, `request`, `notification`, `response`, `invalid`)
- [ ] `ToolCall` is populated with correct `tool_name`, `arguments`, `call_id` for `tools/call` requests
- [ ] `build_error_response` produces valid JSON-RPC error payloads as bytes
- [ ] `tests/test_parser.py` contains 12 tests, all passing
- [ ] No async code in parser — pure synchronous functions only
- [ ] No dependency on `proxy.py` — imports only `models.py` and stdlib `json`
- [ ] `raw` bytes preserved on every `ParsedMessage` instance for zero-cost passthrough
- [ ] All tests run in under 1 second (pure functions, no I/O)