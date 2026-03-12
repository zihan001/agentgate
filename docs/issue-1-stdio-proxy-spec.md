# Issue #1: Implement stdio passthrough proxy

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** Nothing (foundation issue)  
**Blocks:** #2 (JSON-RPC parser), #5 (end-to-end wiring), everything else  
**Target file:** `src/agentgate/proxy.py`  
**Test file:** `tests/test_proxy.py`  
**Estimated effort:** 4–6 hours  
**Ref:** MVP Spec Section 8 (Request Flow), Section 11 Risk 1 (stdio framing)

---

## 1. Objective

Spawn an MCP server as a child process, relay stdin/stdout bidirectionally using frame-aware I/O, and validate that an unmodified MCP client can connect through the proxy and complete the full MCP handshake (`initialize` → `initialized` → `tools/list`).

This is the foundation for all interception. No JSON-RPC parsing. No policy evaluation. No audit logging. Just correct, reliable, bidirectional message relay over MCP stdio transport.

If this doesn't work, the product is dead. De-risk it first.

---

## 2. Scope

### In scope

- `StdioProxy` class in `src/agentgate/proxy.py`
- LSP-style frame reader and writer (`Content-Length` header framing)
- Bidirectional async relay (agent→server, server→agent)
- Child process lifecycle management (spawn, relay, shutdown)
- stderr passthrough (child stderr → proxy stderr)
- Integration test validating MCP handshake through the proxy
- Empirical framing validation script (throwaway, not committed)

### Out of scope

- JSON-RPC message parsing (Issue #2)
- Policy evaluation (Issues #3, #4)
- Audit logging (Issue #12)
- CLI integration / `agentgate start` (Issue #6)
- HTTP/SSE transport
- Windows support
- Any message modification or inspection

---

## 3. Technical decisions

### Decision 1: Frame-aware relay, not raw byte relay

**Choice:** Build the `Content-Length` frame reader/writer from the start.

**Rationale:** Raw byte relay would work for this issue but gets thrown away entirely in Issue #2 when we need to parse individual messages. The frame reader is the foundational I/O primitive for every subsequent issue. It's ~30–40 lines of code. Build it once, validate it now, reuse it forever.

The frame protocol is LSP-style, confirmed by the MCP specification and both the Python and Node SDK implementations:

```
Content-Length: <byte_count>\r\n
\r\n
<byte_count bytes of JSON payload>
```

No other headers are required. `Content-Type` may appear in some implementations but is not required and should be tolerated but not expected.

### Decision 2: asyncio concurrency model

**Choice:** `asyncio` with `asyncio.create_subprocess_exec`.

**Rationale:** The proxy must relay in both directions simultaneously. asyncio gives clean cancellation semantics, avoids thread-safety concerns, and matches the concurrency model of the MCP Python SDK's `StdioServerTransport`. The proxy runs as its own process (spawned by `agentgate start`), so there are no event-loop conflicts.

Three concurrent tasks:
1. `relay(agent_reader, server_writer)` — agent→server
2. `relay(server_reader, agent_writer)` — server→agent
3. `pipe_stderr(child_stderr, sys.stderr)` — stderr passthrough

### Decision 3: stderr handling

**Choice:** Pipe child stderr to proxy stderr, unmodified, via a dedicated async task.

**Rationale:** MCP server errors must be visible to the developer. Don't capture, don't buffer, don't parse. If the Node filesystem server emits a stack trace, the developer sees it immediately.

### Decision 4: Platform support

**Choice:** Linux and macOS only for MVP.

**Rationale:** asyncio stdin/stdout wiring on Windows has known behavioral differences (no `select()` on pipes, `ProactorEventLoop` limitations). Not worth debugging for MVP. Document this constraint.

---

## 4. Implementation steps

Execute these in order. Do not skip Step 1.

### Step 1: Empirical framing validation (~30 min)

**Goal:** Confirm the exact byte-level framing of `@modelcontextprotocol/server-filesystem` before writing any proxy code.

Write a throwaway Python script (not committed to repo) that:

1. Runs `npx -y @modelcontextprotocol/server-filesystem /tmp/agentgate-test`
2. Sends a raw MCP `initialize` request to the child's stdin using Content-Length framing
3. Reads raw bytes from child stdout
4. Prints the raw bytes (including headers) to confirm exact framing

The `initialize` payload:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}
```

Sent as:

```
Content-Length: 156\r\n\r\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}
```

**Verify:**

| Question | Expected | If different |
|----------|----------|--------------|
| Does the server respond with `Content-Length` framing? | Yes | Stop. Investigate the Node SDK's transport. |
| Is the header separator `\r\n\r\n`? | Yes (header line `\r\n` + blank line `\r\n`) | Adjust frame reader. |
| Are there extra headers (`Content-Type`, etc.)? | Possibly. Tolerate but don't require. | Make frame reader skip unknown headers. |
| Does `tools/list` require `initialized` notification first? | Yes — MCP spec requires it | Send `initialized` notification before `tools/list`. |

**This is the single highest-value 30 minutes in the entire project.** Do not write proxy code based on assumptions.

### Step 2: Build the frame reader and writer (~1 hour)

**File:** `src/agentgate/proxy.py`

Two async functions:

**`read_message(reader: asyncio.StreamReader) -> bytes | None`**

1. Read lines from `reader` until a line matching `Content-Length: <n>` is found
2. Continue reading lines until an empty line (`\r\n`) is found (end of headers)
3. Read exactly `n` bytes from `reader`
4. Return the payload bytes
5. Return `None` on EOF (reader at end)

Edge cases to handle:
- Multiple headers before the empty line separator (skip non-Content-Length headers)
- `Content-Length` value is ASCII decimal — parse with `int()`
- EOF mid-header or mid-payload → return `None`, don't raise

**`write_message(writer: asyncio.StreamWriter, payload: bytes) -> None`**

1. Write `Content-Length: {len(payload)}\r\n\r\n` encoded as ASCII
2. Write `payload`
3. Call `writer.drain()`

No buffering tricks. Write the header, write the payload, drain.

### Step 3: Build the relay loop (~30 min)

**File:** `src/agentgate/proxy.py`

```python
async def _relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    label: str,
) -> None:
    """Relay LSP-framed messages from reader to writer until EOF."""
    while True:
        msg = await read_message(reader)
        if msg is None:
            break
        await write_message(writer, msg)
```

The `label` parameter is for debug logging only (e.g. `"agent→server"`, `"server→agent"`). Use `logging.debug` to log message sizes when log level is DEBUG. Do not log message contents at this stage — that's a security concern once real data flows through.

### Step 4: Build the `StdioProxy` class (~1.5 hours)

**File:** `src/agentgate/proxy.py`

```python
class StdioProxy:
    """
    Transparent bidirectional MCP stdio proxy.
    
    Spawns an MCP server as a child process and relays LSP-framed
    messages between the parent's stdin/stdout and the child's
    stdin/stdout.
    """

    def __init__(self, command: list[str]) -> None:
        self.command = command

    async def run(self) -> int:
        """
        Run the proxy. Returns the child process exit code.
        
        Reads from sys.stdin, writes to sys.stdout.
        Spawns self.command as a child process.
        Relays messages bidirectionally until either side closes.
        """
        ...
```

**`run()` implementation sequence:**

1. **Open async stdin/stdout for the agent side.**
   - `agent_reader`: `asyncio.StreamReader` wrapping `sys.stdin.buffer`
   - `agent_writer`: `asyncio.StreamWriter` wrapping `sys.stdout.buffer`
   - Use `asyncio.connect_read_pipe()` and `asyncio.connect_write_pipe()` for proper async wrapping of raw file descriptors.

2. **Spawn the child MCP server process.**
   ```python
   child = await asyncio.create_subprocess_exec(
       *self.command,
       stdin=asyncio.subprocess.PIPE,
       stdout=asyncio.subprocess.PIPE,
       stderr=asyncio.subprocess.PIPE,
   )
   ```

3. **Create three concurrent tasks.**
   ```python
   agent_to_server = asyncio.create_task(
       _relay(agent_reader, child.stdin, "agent→server")
   )
   server_to_agent = asyncio.create_task(
       _relay(child.stdout, agent_writer, "server→agent")
   )
   stderr_task = asyncio.create_task(
       _pipe_stderr(child.stderr)
   )
   ```

4. **Wait for the first relay task to finish.** When one direction hits EOF, the connection is closing.
   ```python
   done, pending = await asyncio.wait(
       [agent_to_server, server_to_agent],
       return_when=asyncio.FIRST_COMPLETED,
   )
   ```

5. **Clean shutdown sequence.**
   - If agent→server finished (agent closed stdin): close child stdin to signal the MCP server.
   - If server→agent finished (MCP server exited): close agent stdout.
   - Cancel the remaining relay task.
   - Cancel the stderr task.
   - Wait for the child process to exit (with a timeout — 5 seconds, then SIGTERM, then SIGKILL).
   - Return the child exit code.

**stderr passthrough:**

```python
async def _pipe_stderr(child_stderr: asyncio.StreamReader) -> None:
    """Pipe child stderr to proxy stderr, line by line."""
    while True:
        line = await child_stderr.readline()
        if not line:
            break
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()
```

### Step 5: Add a `__main__` entry point for manual testing (~15 min)

**File:** `src/agentgate/proxy.py` (at bottom)

```python
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m agentgate.proxy <command> [args...]", file=sys.stderr)
        sys.exit(1)
    proxy = StdioProxy(sys.argv[1:])
    sys.exit(asyncio.run(proxy.run()))
```

This lets you manually test before the CLI exists:
```bash
python -m agentgate.proxy npx -y @modelcontextprotocol/server-filesystem /tmp/test
```

### Step 6: Write integration tests (~1.5 hours)

**File:** `tests/test_proxy.py`

**Test architecture:** The test spawns the proxy as a subprocess (matching real deployment), sends MCP messages to the proxy's stdin, and reads responses from the proxy's stdout. The proxy in turn spawns the MCP server as its child.

```
[Test process] --stdin/stdout--> [Proxy process] --stdin/stdout--> [MCP server process]
```

**Fixture: `proxy_process`**

A pytest fixture that:
1. Creates a temp directory for the filesystem server
2. Starts the proxy as a subprocess: `python -m agentgate.proxy npx -y @modelcontextprotocol/server-filesystem <tmpdir>`
3. Yields the subprocess (with stdin/stdout pipes)
4. On teardown: close stdin, wait for exit, assert clean exit

**Fixture: `mcp_client` (helper functions)**

Utility functions for tests:
- `send_message(proc, payload: dict) -> None` — JSON-encode, frame with Content-Length, write to proc.stdin
- `read_message(proc) -> dict` — read Content-Length frame from proc.stdout, JSON-decode
- `send_notification(proc, method: str, params: dict) -> None` — send without `id` field

**Test 1: `test_initialize_handshake`**

1. Send `initialize` request (id=1)
2. Read response
3. Assert response has `id: 1`
4. Assert `result.protocolVersion` is present
5. Assert `result.capabilities` is present
6. Send `initialized` notification

**Test 2: `test_tools_list`**

1. Complete initialize handshake (reuse helper)
2. Send `tools/list` request (id=2)
3. Read response
4. Assert response has `id: 2`
5. Assert `result.tools` is an array
6. Assert tool names include `read_file`, `write_file`, `list_directory`

**Test 3: `test_tool_call_passthrough`**

1. Complete initialize handshake
2. Create a test file in the temp directory: `/tmp/agentgate-test-xyz/hello.txt` with content `"test content"`
3. Send `tools/call` request: `{"name": "read_file", "arguments": {"path": "<tmpdir>/hello.txt"}}`
4. Read response
5. Assert response contains the file content `"test content"`

**Test 4: `test_clean_shutdown`**

1. Complete initialize handshake
2. Close proxy stdin
3. Wait for proxy process to exit (timeout: 5 seconds)
4. Assert exit code is 0

**Test 5: `test_stderr_passthrough`**

1. Start proxy pointing at a command that writes to stderr (e.g., a tiny Python script that prints to stderr then acts as a minimal MCP server, or just observe stderr from the npx startup)
2. Assert proxy's stderr contains output

Note: This test may be tricky with the Node filesystem server. Alternative: create a minimal Python script that writes to stderr and also responds to `initialize`. Use this as the child command for this test only.

### Handling the npx cold-start problem

`npx -y @modelcontextprotocol/server-filesystem` downloads the package on first run, which takes 10-30 seconds. This will make tests slow and flaky.

**Solution:** Add a `conftest.py` fixture or test session setup that runs `npm install -g @modelcontextprotocol/server-filesystem` once. Then tests use the globally installed binary path instead of `npx -y`. Alternatively, pin the package in a local `package.json` in the test fixtures directory and use `npx` from there.

Preferred approach for MVP: pre-install in test setup, use direct path.

```python
# tests/conftest.py
import subprocess
import shutil

@pytest.fixture(scope="session", autouse=True)
def ensure_mcp_filesystem_server():
    """Ensure the MCP filesystem server is installed before tests run."""
    result = subprocess.run(
        ["npx", "-y", "@modelcontextprotocol/server-filesystem", "--help"],
        capture_output=True, timeout=60,
    )
    # npx will cache after first run; this just warms the cache
```

---

## 5. File inventory

After this issue is complete, the following files are new or modified:

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/proxy.py` | **New** (replace stub) | `read_message`, `write_message`, `_relay`, `_pipe_stderr`, `StdioProxy` class, `__main__` block |
| `tests/test_proxy.py` | **New** (replace stub) | 5 integration tests, `proxy_process` fixture, MCP message helpers |
| `tests/conftest.py` | **Modified** | Add MCP server pre-install fixture, shared message helper utilities |

No other files are touched. `parser.py`, `engine.py`, `policy.py` remain stubs.

---

## 6. Acceptance criteria

All five must pass. If any fail, the framing is wrong.

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | Proxy spawns child MCP server process successfully | `test_initialize_handshake`: child process starts, PID > 0, no crash on spawn |
| AC-2 | MCP `initialize` + `initialized` handshake completes through proxy | `test_initialize_handshake`: response contains `protocolVersion` and `capabilities` |
| AC-3 | `tools/list` returns correct tools through proxy | `test_tools_list`: response includes `read_file` tool with expected input schema |
| AC-4 | `tools/call` passthrough works for a real tool invocation | `test_tool_call_passthrough`: `read_file` returns correct file content through proxy |
| AC-5 | Proxy exits cleanly when agent side disconnects | `test_clean_shutdown`: child process terminated, proxy exit code 0, no zombie processes |

---

## 7. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **MCP framing differs from LSP spec** | Low | Critical | Step 1 empirical validation. Do not skip. If framing is different, adjust `read_message`/`write_message` before writing anything else. |
| **npx cold-start makes tests slow/flaky** | High | Medium | Pre-install the package in test session setup. Pin version. |
| **asyncio stdin/stdout wiring is tricky** | Medium | High | Use `asyncio.connect_read_pipe()` / `asyncio.connect_write_pipe()` with `sys.stdin.buffer` / `sys.stdout.buffer`. Test manually with Step 5 entry point before writing pytest tests. |
| **Deadlock on large messages (>64KB pipe buffer)** | Low | High | asyncio event loop interleaves reads and writes, preventing deadlock. Verify with a test that reads a large file (>64KB) through the proxy. |
| **Child process doesn't exit on stdin close** | Medium | Medium | After closing child stdin, wait with 5s timeout. If still alive, send SIGTERM. If still alive after 2s, send SIGKILL. Log warnings. |
| **Windows incompatibility** | Certain | Low (deferred) | Document Linux/macOS only in README. Don't spend time on this. |

---

## 8. Design constraints for downstream issues

Decisions made here that downstream issues must respect:

1. **`read_message` and `write_message` are the I/O primitives.** Issue #2 (parser) will call `read_message`, parse the JSON payload, and decide whether to intercept. It does not re-implement I/O.

2. **The relay loop is where interception will be inserted.** In Issue #5 (end-to-end wiring), the agent→server relay becomes: `read_message` → `parse` → `evaluate policy` → if allow, `write_message` to server; if block, `write_message` error to agent. The relay function signature will change to accept a callback/hook, but the I/O primitives stay the same.

3. **The proxy is always a separate process.** The `StdioProxy` reads from its own stdin and writes to its own stdout. It is invoked as a command by the MCP client config. This means the proxy's stdin/stdout are the agent's pipes. This is not an in-process wrapper.

4. **asyncio is the concurrency model for the proxy.** All downstream proxy code (parser, engine invocation, audit writes) must be async-compatible or run in an executor. The engine itself can be synchronous (called via `await asyncio.to_thread(engine.evaluate, ...)`) since policy evaluation is CPU-bound and fast (<5ms).

---

## 9. How to verify manually

Before tests exist, you can verify the proxy works with any MCP client. The simplest manual test:

1. Create a temp directory with a test file:
   ```bash
   mkdir -p /tmp/agentgate-test
   echo "hello world" > /tmp/agentgate-test/hello.txt
   ```

2. Run the proxy:
   ```bash
   python -m agentgate.proxy npx -y @modelcontextprotocol/server-filesystem /tmp/agentgate-test
   ```

3. In another terminal, use any MCP client that supports stdio transport (e.g., Claude Desktop, `mcp-client` CLI, or a raw Python script) configured to connect to the proxy process.

4. Alternatively, pipe raw JSON-RPC messages directly:
   ```bash
   printf 'Content-Length: 156\r\n\r\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1.0"}}}' \
     | python -m agentgate.proxy npx -y @modelcontextprotocol/server-filesystem /tmp/agentgate-test
   ```

   You should see a `Content-Length: ...` framed response on stdout containing the `initialize` result.

---

## 10. Definition of done

- [ ] `src/agentgate/proxy.py` contains `StdioProxy` with async frame-aware bidirectional relay
- [ ] `read_message` and `write_message` correctly handle LSP `Content-Length` framing
- [ ] `tests/test_proxy.py` contains 5 integration tests (AC-1 through AC-5)
- [ ] All 5 tests pass on Linux/macOS with `@modelcontextprotocol/server-filesystem`
- [ ] `python -m agentgate.proxy <command>` works for manual testing
- [ ] No JSON-RPC parsing — payload bytes are relayed opaquely
- [ ] Child process is cleaned up on proxy exit (no zombies)
- [ ] Child stderr is visible on proxy stderr