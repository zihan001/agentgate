# Issue #6: Harden `agentgate start` CLI Command

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** #5 (end-to-end wiring — COMPLETE)  
**Blocks:** #7 (PR1 integration tests)  
**Target file:** `src/agentgate/cli.py`  
**Test file:** `tests/test_cli.py`  
**Estimated effort:** 1.5–2 hours  
**Ref:** MVP Spec Section 3 (Single integration path), Section 2 (U3: <2s startup)

---

## 1. Objective

Harden the `agentgate start` CLI command to be production-quality for developer-facing use. The core wiring (policy loading → `StdioProxy`) was completed in Issue #5. This issue addresses the remaining gaps: argument validation, `--` separator handling, missing server command errors, `--verbose` logging, startup banner, env var override for policy path, and CLI-level tests.

The goal is: a developer runs `agentgate start -- npx -y @modelcontextprotocol/server-filesystem /data` and gets correct, helpful behavior in all cases — success, missing policy, bad policy, missing command, bad command.

---

## 2. Scope

### In scope

- Validate `server_command` is non-empty with a clear error message
- Add `--verbose` / `-v` flag that sets `DEBUG` log level on `agentgate.*` loggers
- Add `AGENTGATE_POLICY` env var as override for `--policy` default
- Startup log line: policy path, mode (enforcing/passthrough), server command
- Graceful handling of child process spawn failures (command not found)
- Graceful handling of `KeyboardInterrupt` (Ctrl+C)
- 7 CLI-level tests in `tests/test_cli.py`

### Out of scope

- `agentgate init` (Issue #14)
- `agentgate logs` (Issue #13)
- Policy hot-reload / SIGHUP (v1)
- Daemon mode / background process (v1)
- `--transport` flag for HTTP/SSE (v1)
- Config file for CLI defaults (v1)
- Colorized output (v1)

---

## 3. Current State

The current `cli.py` (from Issue #5) already has:

```python
@main.command()
@click.option("--policy", default="agentgate.yaml", type=click.Path(), help="...")
@click.argument("server_command", nargs=-1, required=True)
def start(policy: str, server_command: tuple[str, ...]) -> None:
    compiled_policy = None
    policy_path = Path(policy)
    if policy_path.exists():
        compiled_policy = load_and_compile(policy_path)  # catches PolicyLoadError
    proxy = StdioProxy(list(server_command), policy=compiled_policy)
    raise SystemExit(asyncio.run(proxy.run()))
```

This works for the happy path. What's missing:

| Gap | Impact |
|-----|--------|
| No validation when `server_command` is empty | Confusing `StdioProxy` crash instead of helpful error |
| No logging setup | Debug output invisible, no startup banner |
| No env var override for policy path | Can't configure via MCP client JSON (no CLI flags in `args`) |
| No graceful `KeyboardInterrupt` handling | Ugly traceback on Ctrl+C |
| No spawn failure handling | Cryptic `FileNotFoundError` if command doesn't exist |
| No startup banner | Developer doesn't know what policy is loaded or what mode the proxy is in |
| No tests | Zero coverage on CLI behavior |

---

## 4. Technical Decisions

### Decision 1: `AGENTGATE_POLICY` env var for MCP client integration

**Choice:** The `--policy` flag defaults to `os.environ.get("AGENTGATE_POLICY", "agentgate.yaml")`.

**Rationale:** When AgentGate is configured as an MCP server command in `claude_desktop_config.json` or similar, the `args` array can't easily pass `--policy /path/to/policy.yaml` before `--`. The env var lets users configure the policy path without modifying the CLI args. This is the standard pattern for CLI tools used as subprocess commands.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentgate",
      "args": ["start", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": { "AGENTGATE_POLICY": "/home/user/my-policy.yaml" }
    }
  }
}
```

### Decision 2: Startup banner goes to stderr, not stdout

**Choice:** All CLI logging and banner output goes to `sys.stderr`.

**Rationale:** `sys.stdout` is the MCP stdio transport. Any non-JSON-RPC output on stdout will corrupt the MCP framing and break the agent connection. This is non-negotiable. Click's `click.echo(..., err=True)` and Python's `logging` (configured to stderr) handle this correctly.

### Decision 3: `--verbose` sets DEBUG on `agentgate.*` loggers only

**Choice:** `-v` / `--verbose` sets `logging.DEBUG` on the `agentgate` logger namespace. Default is `WARNING`.

**Rationale:** DEBUG output from the proxy includes message sizes and relay directions — useful for diagnosing framing issues. But it should never be on by default because it adds latency and noise. Limiting to the `agentgate` namespace avoids flooding with asyncio internals or third-party library debug output.

### Decision 4: Empty `server_command` is caught at the CLI level

**Choice:** If `server_command` is empty after Click parsing, print an error with usage hint and exit 1. Do not call `StdioProxy`.

**Rationale:** Click's `required=True` on `nargs=-1` doesn't enforce non-empty (it allows zero args). Without validation, an empty command list propagates to `asyncio.create_subprocess_exec()` which raises an unhelpful `IndexError`. Catch it early with a message like: `Error: No server command provided. Usage: agentgate start -- <command> [args...]`

### Decision 5: Catch `FileNotFoundError` from child spawn

**Choice:** Wrap `asyncio.run(proxy.run())` in a try/except that catches `FileNotFoundError` and `PermissionError`, prints a clear message, and exits 1.

**Rationale:** If the user types `agentgate start -- nxp -y ...` (typo), `asyncio.create_subprocess_exec` raises `FileNotFoundError`. The developer needs to see `Error: Command not found: 'nxp'. Is it installed and on your PATH?`, not a Python traceback.

### Decision 6: `KeyboardInterrupt` exits cleanly with code 130

**Choice:** Catch `KeyboardInterrupt` at the top of `start()`, print nothing (or a brief "Interrupted"), and exit 130 (Unix convention: 128 + signal number for SIGINT=2).

**Rationale:** Ctrl+C during proxy operation should not produce a traceback. Exit code 130 is the standard Unix convention and lets callers distinguish "user interrupted" from "error."

---

## 5. Implementation

### 5.1 Logging setup helper

Add to `cli.py`:

```python
def _setup_logging(verbose: bool) -> None:
    """Configure logging for the agentgate namespace."""
    level = logging.DEBUG if verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    logger = logging.getLogger("agentgate")
    logger.setLevel(level)
    logger.addHandler(handler)
```

### 5.2 Updated `start` command

```python
@main.command()
@click.option(
    "--policy",
    default=None,
    type=click.Path(),
    help="Path to the policy file. Default: $AGENTGATE_POLICY or agentgate.yaml.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
@click.argument("server_command", nargs=-1, required=True)
def start(policy: str | None, verbose: bool, server_command: tuple[str, ...]) -> None:
    """Start the AgentGate proxy wrapping an MCP server.

    Usage: agentgate start [--policy FILE] [--verbose] -- <command> [args...]
    """
    import asyncio
    from pathlib import Path
    from agentgate.proxy import StdioProxy

    _setup_logging(verbose)

    # --- Validate server command ---
    if not server_command:
        click.echo(
            "Error: No server command provided.\n"
            "Usage: agentgate start -- <command> [args...]",
            err=True,
        )
        raise SystemExit(1)

    # --- Resolve policy path ---
    if policy is None:
        policy = os.environ.get("AGENTGATE_POLICY", "agentgate.yaml")
    policy_path = Path(policy)

    # --- Load policy ---
    compiled_policy = None
    if policy_path.exists():
        from agentgate.policy import PolicyLoadError, load_and_compile
        try:
            compiled_policy = load_and_compile(policy_path)
        except PolicyLoadError as e:
            click.echo(f"Error loading policy: {e}", err=True)
            raise SystemExit(1)

    # --- Startup banner ---
    mode = "enforcing" if compiled_policy is not None else "passthrough"
    policy_display = str(policy_path) if compiled_policy else "(none)"
    rule_count = len(compiled_policy.config.policies) if compiled_policy else 0
    click.echo(
        f"AgentGate v{__version__} | mode={mode} | policy={policy_display} "
        f"| rules={rule_count} | server={server_command[0]}",
        err=True,
    )

    # --- Run proxy ---
    proxy = StdioProxy(list(server_command), policy=compiled_policy)
    try:
        exit_code = asyncio.run(proxy.run())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except FileNotFoundError:
        click.echo(
            f"Error: Command not found: '{server_command[0]}'. "
            f"Is it installed and on your PATH?",
            err=True,
        )
        raise SystemExit(1)
    except PermissionError:
        click.echo(
            f"Error: Permission denied running: '{server_command[0]}'.",
            err=True,
        )
        raise SystemExit(1)
    raise SystemExit(exit_code)
```

### 5.3 Required import additions

At the top of `cli.py`, add:

```python
import logging
import os
import sys
```

---

## 6. What Changes in Each File

| File | Change type | What changes |
|------|-------------|--------------|
| `src/agentgate/cli.py` | **Moderate edit** | Add `_setup_logging`, update `start` with env var, verbose flag, validation, banner, error handling (~40 net new lines) |
| `tests/test_cli.py` | **New** | 7 CLI tests |

No changes to `proxy.py`, `parser.py`, `policy.py`, `engine.py`, or `models.py`.

---

## 7. Test Plan

**File:** `tests/test_cli.py`

Tests use `click.testing.CliRunner` for unit-level CLI testing (no subprocess, no real proxy). For tests that need the proxy to actually run, use subprocess with a timeout.

### Test 1: `test_start_no_server_command`

**Action:** Invoke `start` with no arguments via `CliRunner`.  
**Assert:** Exit code 1. Output contains `"No server command"`.

### Test 2: `test_start_bad_policy_file`

**Setup:** Write invalid YAML to a temp file.  
**Action:** Invoke `start --policy <tmpfile> -- echo hello` via `CliRunner`.  
**Assert:** Exit code 1. Output contains `"Error loading policy"`.

### Test 3: `test_start_missing_policy_is_passthrough`

**Action:** Invoke `start --policy /nonexistent/policy.yaml -- echo hello` via subprocess with short timeout.  
**Assert:** Stderr contains `"passthrough"`. Process starts (may exit quickly since `echo` isn't an MCP server — that's fine, we're testing CLI behavior not proxy relay).

### Test 4: `test_start_command_not_found`

**Action:** Invoke `agentgate start -- nonexistent_binary_xyz` via subprocess.  
**Assert:** Exit code 1. Stderr contains `"Command not found"`.

### Test 5: `test_start_verbose_flag`

**Action:** Invoke `start -v --policy /nonexistent/policy.yaml -- echo hello` via subprocess.  
**Assert:** Stderr contains `"DEBUG"` or the startup banner. Verbose logging is active.

### Test 6: `test_start_env_var_policy_override`

**Setup:** Write a valid minimal policy to a temp file. Set `AGENTGATE_POLICY` env var to that path.  
**Action:** Invoke `start -- echo hello` via subprocess (no `--policy` flag).  
**Assert:** Stderr contains `"enforcing"` and the policy path from the env var.

### Test 7: `test_start_banner_output`

**Setup:** Write a valid policy with 2 rules to a temp file.  
**Action:** Invoke `start --policy <tmpfile> -- echo hello` via subprocess.  
**Assert:** Stderr contains `"AgentGate v"`, `"mode=enforcing"`, `"rules=2"`.

### Test notes

- Tests 1 and 2 use `CliRunner` (in-process, fast, no subprocess).
- Tests 3–7 use `subprocess.run` with a short timeout (2s) because the proxy needs to actually start to emit the banner. The child command (`echo hello`) will fail the MCP handshake and the proxy will exit — that's fine for these tests.
- Test 4 specifically: the `FileNotFoundError` propagates through `asyncio.run()` and is caught by the `except FileNotFoundError` in `start()`.

---

## 8. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | `agentgate start` with no server command prints helpful error and exits 1 | Test 1 |
| AC-2 | `agentgate start` with invalid policy prints `PolicyLoadError` message and exits 1 | Test 2 |
| AC-3 | `agentgate start` with missing policy file runs in passthrough mode | Test 3 |
| AC-4 | `agentgate start` with nonexistent command prints "Command not found" and exits 1 | Test 4 |
| AC-5 | `AGENTGATE_POLICY` env var overrides default policy path | Test 6 |
| AC-6 | Startup banner on stderr shows version, mode, policy path, rule count, server command | Test 7 |
| AC-7 | All existing tests still pass (56 tests from Issues #1–#5) | `pytest` full suite |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `FileNotFoundError` not raised by `asyncio.run` for bad commands | Low | Medium | `asyncio.create_subprocess_exec` raises `FileNotFoundError` synchronously before the event loop runs. If it doesn't, the error will surface as a task exception in `proxy.run()`. Test 4 confirms the behavior. |
| `CliRunner` doesn't exercise real subprocess path | Medium | Low | Tests 3–7 use real subprocess. `CliRunner` is only for pure arg-parsing tests (1, 2). |
| Startup banner adds latency | Very Low | None | It's one `sys.stderr.write` call. Unmeasurable. |
| `--verbose` leaks sensitive info in production | Low | Low | Debug logging only shows message sizes and relay directions, not message contents (established in Issue #1). Tool call arguments are never logged at DEBUG level in the proxy. |
| Env var `AGENTGATE_POLICY` conflicts with `--policy` flag | None | None | `--policy` takes precedence when explicitly passed (it's `not None`). Env var is only the default when `--policy` is omitted. Standard CLI convention. |

---

## 10. Design Constraints for Downstream Issues

1. **All CLI output goes to stderr.** This is a permanent constraint. Stdout is the MCP transport. Any future CLI commands that run the proxy (`start`, hypothetical `start --watch`) must never write to stdout. `logs` and `init` can write to stdout since they don't run the proxy.

2. **`_setup_logging` is the canonical logging setup.** Issue #13 (`agentgate logs`) and any future CLI commands that need logging should call `_setup_logging` or a shared variant. Don't add a second logging configuration path.

3. **`AGENTGATE_POLICY` env var is the integration contract.** MCP client configs (Claude Desktop, Cursor, etc.) use this to specify policy paths. Document it in the README and `agentgate start --help`.

4. **Exit codes are stable:**
   - `0` — clean shutdown
   - `1` — configuration or runtime error
   - `130` — user interrupt (Ctrl+C)
   - Child process exit code — propagated when the MCP server exits with non-zero

---

## 11. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/cli.py` | **Moderate edit** | `_setup_logging`, updated `start` command with validation, env var, verbose, banner, error handling |
| `tests/test_cli.py` | **New** | 7 CLI tests |

No other files are touched.

---

## 12. Definition of Done

- [ ] `agentgate start` with no server command prints helpful error and exits 1
- [ ] `agentgate start` with bad policy prints `PolicyLoadError` message and exits 1
- [ ] `agentgate start` with no policy file runs in passthrough mode with banner showing `mode=passthrough`
- [ ] `agentgate start` with valid policy shows banner with `mode=enforcing`, rule count, policy path
- [ ] `agentgate start` with nonexistent command prints `"Command not found"` and exits 1
- [ ] `Ctrl+C` exits cleanly with code 130, no traceback
- [ ] `--verbose` / `-v` enables DEBUG logging on `agentgate.*` loggers
- [ ] `AGENTGATE_POLICY` env var overrides default policy path when `--policy` is not passed
- [ ] All output goes to stderr (stdout is reserved for MCP transport)
- [ ] `tests/test_cli.py` contains 7 tests, all passing
- [ ] All existing tests (56 from Issues #1–#5) still pass
- [ ] Total test count: 63+ (56 existing + 7 CLI = 63)