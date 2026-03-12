# Issue #5: Wire Proxy + Parser + Policy + Engine End-to-End

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** #1 (stdio proxy — COMPLETE), #2 (JSON-RPC parser — COMPLETE), #3 (policy loader — COMPLETE), #4 (rule engine — COMPLETE)  
**Blocks:** #6 (CLI wiring), #7 (PR1 integration tests), #11 (chain detection extends this)  
**Target file:** `src/agentgate/proxy.py`  
**Test file:** `tests/test_proxy_policy.py`  
**Estimated effort:** 3–4 hours  
**Ref:** MVP Spec Section 8 (Request Flow steps 1–7)

---

## 1. Objective

Transform the proxy from a dumb relay into a policy-enforcing interceptor. The agent→server relay currently calls `read_message → write_message` opaquely. After this issue, the agent→server path becomes: `read_message → parse_message → evaluate → write_message (to server or error to agent)`. The server→agent path stays unchanged (opaque relay).

This is the integration milestone. No new modules. No new data models. No new algorithms. Just wiring four existing, tested modules together in the proxy's hot path and confirming the full loop works.

---

## 2. Scope

### In scope

- Modify `StdioProxy` to accept a `CompiledPolicy` (or `None` for passthrough mode)
- Modify the agent→server relay to parse messages and intercept `tools/call` requests
- Call `engine.evaluate()` on intercepted tool calls
- Return JSON-RPC error responses to the agent for blocked calls
- Forward allowed calls (and all non-`tools/call` messages) using original raw bytes
- Modify `cli.py` `start` command to load policy and pass it to the proxy
- 8 integration tests validating allow, block, passthrough, and error format
- Update `build_error_response` to support `error.data` field

### Out of scope

- Detector pipeline (step 1 of engine — Issue #26)
- `param_rule` evaluation (step 4 — Issue #8)
- `chain_rule` evaluation (step 5 — Issue #11)
- Session store
- Audit logging
- Response interception (server→agent remains opaque relay)
- Policy hot-reload
- Any new Pydantic models

---

## 3. Technical Decisions

### Decision 1: Policy is loaded once at startup, passed into `StdioProxy`

**Choice:** `StdioProxy.__init__(self, command: list[str], policy: CompiledPolicy | None = None)`. The CLI loads the policy, passes it in. The proxy never touches YAML or the filesystem.

**Rationale:** Separation of concerns. The CLI handles config (file paths, error messages on bad YAML). The proxy handles runtime (relay, intercept, evaluate). This also keeps `StdioProxy` testable — tests can construct `CompiledPolicy` objects programmatically without temp files. `policy=None` preserves backward compatibility for existing proxy tests that don't use policies.

### Decision 2: Replace `_relay` with `_intercepting_relay` for agent→server direction only

**Choice:** The agent→server task uses a new `_intercepting_relay` function. The server→agent task keeps using the existing `_relay` unchanged.

**Rationale:** Only agent→server traffic contains `tools/call` requests that need interception. Server→agent traffic is responses — the proxy must not modify or inspect them in this issue (response scanning is PR2+). Keeping the server→agent relay untouched means zero risk of breaking response forwarding.

### Decision 3: Non-`tools/call` messages are forwarded using `parsed.raw` (zero re-serialization)

**Choice:** Every non-`tools/call` message (including `kind="invalid"`) is forwarded by writing `parsed.raw` directly. No re-encoding, no modification.

**Rationale:** This is the contract from Issue #2. `parsed.raw` is byte-identical to the original payload. Re-serializing would risk JSON formatting differences that could break MCP clients. The parser was designed for this — use it.

### Decision 4: Blocked calls get a JSON-RPC error with `error.data`

**Choice:** When the engine returns `action="block"`, the proxy sends:

```json
{
  "jsonrpc": "2.0",
  "id": "<request_id>",
  "error": {
    "code": -32600,
    "message": "Tool call blocked by policy",
    "data": {
      "matched_rule": "<rule name or null>",
      "matched_detector": "<detector name or null>",
      "message": "<block reason>"
    }
  }
}
```

**Rationale:** `-32600` (Invalid Request) is the standard JSON-RPC code for "server refused to process." The `error.data` field is allowed by JSON-RPC 2.0 spec for additional structured info. MCP clients that understand AgentGate can surface `data.message` to the user. Clients that don't just see the top-level `error.message`.

### Decision 5: `build_error_response` gets an optional `data` parameter

**Choice:** Extend `build_error_response(request_id, code, message, data=None)` in `parser.py` to accept an optional `data` dict. If provided, it's included in the `error` object.

**Rationale:** Minimal change to existing code. Existing callers (tests, future uses) aren't broken — `data` defaults to `None` and the error object is unchanged when absent. This is a backward-compatible addition.

### Decision 6: `policy=None` means full passthrough (no interception)

**Choice:** When `StdioProxy` receives `policy=None`, the agent→server relay behaves identically to the current opaque relay. No parsing, no engine calls.

**Rationale:** Existing proxy tests (Issue #1) don't use policies and must continue to pass without modification. This is backward compatibility, not a feature flag.

### Decision 7: Engine evaluation is called synchronously in the async relay

**Choice:** Call `engine.evaluate(tool_call, policy)` directly (no `asyncio.to_thread`).

**Rationale:** `evaluate()` is <1ms. It's a pure function doing set lookups. `to_thread` adds ~50μs of overhead and complexity for zero benefit. The proxy is single-agent — there's no concurrent evaluation contention. If profiling later shows this matters (it won't), wrapping in `to_thread` is a one-line change.

---

## 4. Implementation

### 4.1 Modify `build_error_response` in `parser.py`

Add optional `data` parameter:

```python
def build_error_response(
    request_id: str | int, code: int, message: str, data: dict | None = None
) -> bytes:
    """Build a JSON-RPC error response payload as bytes (not LSP-framed).

    The caller wraps this with write_message() which adds Content-Length framing.
    """
    error_obj: dict = {"code": code, "message": message}
    if data is not None:
        error_obj["data"] = data
    return json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": error_obj,
    }).encode()
```

This is a 3-line diff. Existing test `test_build_error_response` continues to pass (no `data` arg = no `data` field).

### 4.2 Add `_intercepting_relay` to `proxy.py`

New function alongside existing `_relay`:

```python
from agentgate.engine import evaluate
from agentgate.parser import build_error_response, parse_message
from agentgate.policy import CompiledPolicy


async def _intercepting_relay(
    reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter | asyncio.WriteTransport,
    agent_writer: asyncio.StreamWriter | asyncio.WriteTransport,
    policy: CompiledPolicy,
    label: str,
) -> None:
    """Relay with policy interception: parse tool calls, evaluate, block or forward."""
    while True:
        payload = await read_message(reader)
        if payload is None:
            log.debug("%s: EOF", label)
            break

        parsed = parse_message(payload)

        if parsed.kind == "tool_call" and parsed.tool_call is not None:
            decision = evaluate(parsed.tool_call, policy)
            log.debug(
                "%s: %s -> %s (rule=%s)",
                label,
                parsed.tool_call.tool_name,
                decision.action,
                decision.matched_rule,
            )
            if decision.action == "block":
                error_data = {
                    "matched_rule": decision.matched_rule,
                    "matched_detector": decision.matched_detector,
                    "message": decision.message,
                }
                error_payload = build_error_response(
                    parsed.request_id, -32600, "Tool call blocked by policy", data=error_data
                )
                await write_message(agent_writer, error_payload)
                continue

        # Allow: forward original bytes (zero re-serialization)
        log.debug("%s: forwarding %d bytes", label, len(payload))
        await write_message(server_writer, payload)
```

Key properties:

- If `parsed.kind != "tool_call"`, message is forwarded unchanged (this includes `request`, `notification`, `response`, `invalid`)
- If `parsed.kind == "tool_call"` and decision is `allow`, the original `payload` bytes are forwarded (not re-serialized)
- If decision is `block`, error goes to `agent_writer` (back to the agent), and the message is NOT forwarded to the server
- The `continue` after writing the error skips the `write_message(server_writer, ...)` — blocked calls never reach the MCP server

### 4.3 Modify `StdioProxy.__init__` and `run()`

**Constructor change:**

```python
class StdioProxy:
    def __init__(self, command: list[str], policy: CompiledPolicy | None = None) -> None:
        self.command = command
        self.policy = policy
```

**In `run()`, change the agent→server task creation:**

```python
# Replace this:
agent_to_server = asyncio.create_task(_relay(agent_reader, child.stdin, "agent->server"))

# With this:
if self.policy is not None:
    agent_to_server = asyncio.create_task(
        _intercepting_relay(
            agent_reader, child.stdin, agent_write_transport, self.policy, "agent->server"
        )
    )
else:
    agent_to_server = asyncio.create_task(_relay(agent_reader, child.stdin, "agent->server"))
```

Everything else in `run()` stays identical. The server→agent relay, stderr task, shutdown sequence, child process lifecycle — none of it changes.

### 4.4 Modify `cli.py` `start` command

```python
@main.command()
@click.option(
    "--policy",
    default="agentgate.yaml",
    type=click.Path(),
    help="Path to the policy file (default: agentgate.yaml).",
)
@click.argument("server_command", nargs=-1, required=True)
def start(policy: str, server_command: tuple[str, ...]) -> None:
    """Start the AgentGate proxy wrapping an MCP server."""
    import asyncio
    from pathlib import Path

    from agentgate.proxy import StdioProxy

    compiled_policy = None
    policy_path = Path(policy)
    if policy_path.exists():
        from agentgate.policy import PolicyLoadError, load_and_compile
        try:
            compiled_policy = load_and_compile(policy_path)
        except PolicyLoadError as e:
            click.echo(f"Error loading policy: {e}", err=True)
            raise SystemExit(1)

    proxy = StdioProxy(list(server_command), policy=compiled_policy)
    raise SystemExit(asyncio.run(proxy.run()))
```

Behavior:

- If `agentgate.yaml` exists, load and compile it. On error, print message and exit 1.
- If `agentgate.yaml` doesn't exist, run in passthrough mode (`policy=None`). This is intentional — it means `agentgate start -- <cmd>` works immediately without `agentgate init`. The proxy is useful as a transparent wrapper even before the user writes a policy.
- The `--policy` flag lets the user point at a different file.

---

## 5. What Changes in Each File

| File | Change type | What changes |
|------|-------------|--------------|
| `src/agentgate/parser.py` | **Minor edit** | Add `data: dict \| None = None` param to `build_error_response` |
| `src/agentgate/proxy.py` | **Moderate edit** | Add `_intercepting_relay` function (~25 lines). Modify `StdioProxy.__init__` (add `policy` param). Modify `run()` (4-line conditional). Add imports for `parse_message`, `build_error_response`, `evaluate`, `CompiledPolicy`. |
| `src/agentgate/cli.py` | **Moderate edit** | Add policy loading to `start` command (~10 lines) |
| `tests/helpers/proxy_with_policy.py` | **New** | Test harness script for spawning proxy with policy |
| `tests/test_proxy_policy.py` | **New** | 8 integration tests |
| `tests/conftest.py` | **Minor edit** | Add `proxy_with_policy` factory fixture |

No changes to `models.py`, `policy.py`, or `engine.py`.

---

## 6. Test Architecture

### Test harness: `tests/helpers/proxy_with_policy.py`

A tiny script that imports `StdioProxy` directly and runs it with a `CompiledPolicy`. Tests spawn this script as a subprocess with a policy path passed via env var. This avoids testing through the CLI and lets us construct policies from temp YAML files.

```python
# tests/helpers/proxy_with_policy.py
"""Test harness: runs StdioProxy with a policy loaded from AGENTGATE_TEST_POLICY env var."""
import asyncio
import os
import sys

from agentgate.policy import load_and_compile
from agentgate.proxy import StdioProxy

policy_path = os.environ.get("AGENTGATE_TEST_POLICY")
policy = load_and_compile(policy_path) if policy_path else None
server_cmd = sys.argv[1:]
proxy = StdioProxy(server_cmd, policy=policy)
sys.exit(asyncio.run(proxy.run()))
```

### Fixture: `proxy_with_policy` (in `conftest.py`)

Factory fixture that writes a YAML policy to `tmp_path`, spawns the proxy harness with the echo server, and yields the subprocess.

```python
PROXY_WITH_POLICY_PATH = str(Path(__file__).parent / "helpers" / "proxy_with_policy.py")

@pytest.fixture()
def proxy_with_policy(tmp_path, echo_server_cmd):
    """Factory: spawn a proxy with a given policy YAML string. Returns subprocess.Popen."""
    procs = []

    def _spawn(yaml_content: str) -> subprocess.Popen:
        policy_path = tmp_path / "agentgate.yaml"
        policy_path.write_text(yaml_content, encoding="utf-8")

        env = os.environ.copy()
        env["AGENTGATE_TEST_POLICY"] = str(policy_path)

        cmd = [sys.executable, PROXY_WITH_POLICY_PATH] + echo_server_cmd
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(Path(__file__).parent.parent),
        )
        procs.append(proc)
        return proc

    yield _spawn

    for proc in procs:
        if proc.poll() is None:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
```

Tests reuse `send_message`, `read_message`, and `do_initialize` helpers from `test_proxy.py`. Move these to `conftest.py` or a shared `tests/helpers/mcp_client.py` module so both test files can import them.

---

## 7. Test Plan

**File:** `tests/test_proxy_policy.py`

All tests are integration tests. Each spawns a proxy subprocess wrapping the echo MCP server with a specific policy.

### Policy YAML snippets used by tests

```python
ALLOW_ECHO = """\
version: "0.1"
policies:
  - name: allow-echo
    type: tool_allow
    tools:
      - echo_tool
"""

BLOCK_ECHO = """\
version: "0.1"
policies:
  - name: block-echo
    type: tool_block
    tools:
      - echo_tool
"""

ALLOW_OTHER_ONLY = """\
version: "0.1"
policies:
  - name: allow-other
    type: tool_allow
    tools:
      - other_tool
"""

DEFAULT_BLOCK = """\
version: "0.1"
settings:
  default_decision: block
"""

MIXED_POLICY = """\
version: "0.1"
policies:
  - name: allow-tools
    type: tool_allow
    tools:
      - echo_tool
      - blocked_tool
  - name: block-dangerous
    type: tool_block
    tools:
      - blocked_tool
"""
```

### Test 1: `test_allowed_tool_passes_through`

**Setup:** Policy = `ALLOW_ECHO`.  
**Action:** Initialize, then `tools/call` with `name: echo_tool, arguments: {"message": "hello"}`.  
**Assert:** Response has `result` (not `error`). Result content contains `"hello"`.

### Test 2: `test_blocked_tool_returns_error`

**Setup:** Policy = `BLOCK_ECHO`.  
**Action:** Initialize, then `tools/call` with `name: echo_tool`.  
**Assert:** Response has `error`, not `result`. `error["code"] == -32600`. `error["message"] == "Tool call blocked by policy"`. `error["data"]["matched_rule"] == "block-echo"`. `error["data"]["message"]` contains `"blocked"`.

### Test 3: `test_tool_not_on_allowlist_blocked`

**Setup:** Policy = `ALLOW_OTHER_ONLY`.  
**Action:** Initialize, then `tools/call` with `name: echo_tool`.  
**Assert:** Response has `error`. `error["data"]["message"]` contains `"not on the allowlist"`.

### Test 4: `test_non_tool_call_messages_pass_through`

**Setup:** Policy = `BLOCK_ECHO` (aggressive — blocks echo_tool).  
**Action:** Send `initialize` (id=1). Send `initialized` notification. Send `tools/list` (id=2).  
**Assert:** Initialize response has `result` with `protocolVersion`. Tools/list response has `result` with tools array. The block rule does NOT affect non-`tools/call` messages.

### Test 5: `test_no_policy_means_passthrough`

**Setup:** No policy (use existing `proxy_process` fixture from conftest, which spawns proxy without policy).  
**Action:** Initialize, then `tools/call` with `name: echo_tool`.  
**Assert:** Response has `result`. Full passthrough behavior unchanged.

### Test 6: `test_default_block_with_no_rules`

**Setup:** Policy = `DEFAULT_BLOCK`.  
**Action:** Initialize, then `tools/call` with `name: echo_tool`.  
**Assert:** Response has `error`. Default decision is block, so any tool call is blocked.

### Test 7: `test_error_response_format`

**Setup:** Policy = `BLOCK_ECHO`.  
**Action:** `tools/call` with `name: echo_tool`, `id: 42`.  
**Assert:**
- `response["id"] == 42`
- `response["jsonrpc"] == "2.0"`
- `response["error"]["code"] == -32600`
- `response["error"]["message"] == "Tool call blocked by policy"`
- `response["error"]["data"]` is a dict
- `response["error"]["data"]["matched_rule"] == "block-echo"`
- `response["error"]["data"]["matched_detector"] is None`
- `response["error"]["data"]["message"]` is a non-empty string

### Test 8: `test_multiple_calls_mixed_decisions`

**Setup:** Policy = `MIXED_POLICY` (allows echo_tool, blocks blocked_tool).  
**Action:** Initialize. Send `tools/call` for `echo_tool` (id=10). Send `tools/call` for `blocked_tool` (id=11). Send `tools/call` for `echo_tool` again (id=12).  
**Assert:**
- Response id=10 has `result` (allowed)
- Response id=11 has `error` (blocked)
- Response id=12 has `result` (allowed)
- Proxy correctly handles interleaved allow/block without state corruption

---

## 8. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| AC-1 | Tool calls allowed by policy are forwarded to MCP server and responses returned to agent | Tests 1, 5, 8 |
| AC-2 | Tool calls blocked by policy return JSON-RPC error to agent and are NOT forwarded to MCP server | Tests 2, 3, 6, 8 |
| AC-3 | JSON-RPC error response includes `error.data` with `matched_rule`, `matched_detector`, `message` | Tests 2, 7 |
| AC-4 | Non-`tools/call` messages (initialize, notifications, tools/list, responses) are always forwarded regardless of policy | Test 4 |
| AC-5 | Proxy with no policy (`policy=None`) behaves as full passthrough (backward compatible) | Test 5 |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **`_intercepting_relay` needs both `server_writer` and `agent_writer`** — different from `_relay` signature | Certain | Low | This is a design choice, not a risk. The function takes two writers explicitly. The agent→server relay needs the agent writer to send errors back. |
| **Existing proxy tests break** | Low | Medium | `policy=None` default means `StdioProxy(command)` still works exactly as before. The `proxy_process` fixture in `conftest.py` doesn't pass a policy. Existing tests use the opaque `_relay` path. Run existing tests first to confirm. |
| **Error response timing — agent sends next request before error is written** | Very Low | Low | Stdio is synchronous from the agent's perspective. The agent sends a request and waits for a response. The error response satisfies that wait. No race condition. |
| **`parse_message` on large payloads adds latency** | Very Low | None | `json.loads` on typical tool call payloads (<1KB) is <0.1ms. Not measurable. |
| **Blocked call's `id` is wrong** | Low | High | `parsed.request_id` comes directly from the JSON-RPC `id` field. `build_error_response` uses it. If the agent sent id=42, the error has id=42. Verified by Test 7. |
| **Import cycle: proxy.py → parser.py, engine.py, policy.py** | None | None | All imports are one-directional. `proxy` depends on `parser`, `engine`, and `policy`. None of those depend on `proxy`. No circular imports. |

---

## 10. Design Constraints for Downstream Issues

1. **`_intercepting_relay` is where detectors and param/chain rules will execute.** Issue #26 (wire detectors) adds detector calls between `parse_message` and `evaluate`. Issue #8 (param_rule) and #11 (chain_rule) are implemented inside `engine.evaluate` — the proxy doesn't change for those, the engine just does more work.

2. **Session store writes will be added here.** Issue #11 needs the proxy to record tool call results in the session store. This means the server→agent relay (or a post-forward hook) will eventually write to the session store. But that's Issue #11's problem, not this one.

3. **Audit writes will be added here.** Issue #12 adds an async audit write after each decision. The insertion point is in `_intercepting_relay`, after the allow/block decision. But that's Issue #12's problem.

4. **The `_intercepting_relay` function signature will grow.** It will eventually need `session_store` and `audit_writer` parameters. For now, it takes only what it needs: `reader`, `server_writer`, `agent_writer`, `policy`, `label`. New params will be added with defaults when those issues land.

5. **`build_error_response` `data` field is the agent-facing contract.** MCP clients that integrate with AgentGate can parse `error.data` for structured block information. This format must be stable.

---

## 11. How This Integrates (Visual)

### Before (Issue #1 — opaque relay)

```
Agent stdin ──read_message──→ raw bytes ──write_message──→ MCP server stdin
MCP server stdout ──read_message──→ raw bytes ──write_message──→ Agent stdout
```

### After (Issue #5 — intercepting relay)

```
Agent stdin ──read_message──→ bytes ──parse_message──→ ParsedMessage
                                                          │
                                                   kind == tool_call?
                                                     │           │
                                                    YES          NO
                                                     │           │
                                              evaluate(policy)   │
                                                │        │       │
                                              BLOCK    ALLOW     │
                                                │        │       │
                                    write_message     write_message
                                    (error → agent)  (raw → server)
                                                         │       │
                                                         └───────┘

MCP server stdout ──read_message──→ raw bytes ──write_message──→ Agent stdout
                                    (unchanged — opaque relay)
```

---

## 12. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/parser.py` | **Minor edit** | Add `data` param to `build_error_response` |
| `src/agentgate/proxy.py` | **Moderate edit** | Add `_intercepting_relay`, modify `StdioProxy.__init__` and `run()`, add imports |
| `src/agentgate/cli.py` | **Moderate edit** | Policy loading in `start` command |
| `tests/helpers/proxy_with_policy.py` | **New** | Test harness script for spawning proxy with policy |
| `tests/test_proxy_policy.py` | **New** | 8 integration tests |
| `tests/conftest.py` | **Minor edit** | Add `proxy_with_policy` factory fixture, extract shared MCP client helpers |

No changes to `models.py`, `policy.py`, or `engine.py`.

---

## 13. Definition of Done

- [ ] `StdioProxy` accepts optional `CompiledPolicy` and intercepts `tools/call` requests when policy is present
- [ ] Blocked tool calls return JSON-RPC error with `error.code=-32600`, `error.data` containing `matched_rule`, `matched_detector`, `message`
- [ ] Allowed tool calls are forwarded using original raw bytes (zero re-serialization)
- [ ] Non-`tools/call` messages always pass through regardless of policy
- [ ] `policy=None` preserves full passthrough behavior (existing proxy tests unbroken)
- [ ] `cli.py start` loads policy from file, handles `PolicyLoadError` gracefully
- [ ] `cli.py start` runs in passthrough mode if policy file does not exist
- [ ] `build_error_response` supports optional `data` dict parameter
- [ ] `tests/test_proxy_policy.py` contains 8 integration tests, all passing
- [ ] All existing tests (`test_proxy.py`, `test_parser.py`, `test_policy.py`, `test_engine.py`, `test_models.py`) still pass
- [ ] Total test count: 53+ (11 models + 12 parser + 10 policy + 10 engine + 5 proxy + 8 proxy_policy = 56)