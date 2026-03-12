# Issue #7: PR1 Integration Tests + Shared Test Fixtures

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** #5 (end-to-end wiring — COMPLETE), #6 (CLI hardening — COMPLETE)  
**Blocks:** #15 (acceptance tests), #8 (param_rule — needs `make_tool_call`), #11 (chain detection — needs `sample_policy`)  
**Target files:** `tests/test_integration.py`, `tests/conftest.py`  
**Estimated effort:** 2–3 hours  
**Ref:** MVP Spec Section 2 (F1, F2), Section 6 (AT-4 benign ops), Section 10 (PR1 deliverables)

---

## 1. Objective

Close out PR1 with two deliverables:

1. **Integration tests that exercise the full proxy pipeline against richer policy scenarios** — specifically testing blocklist-beats-allowlist through the live proxy (currently only unit-tested in `test_engine.py`), multi-rule policies with param_rule stubs present, and the `agentgate start` CLI as the entry point (currently only tested via the `proxy_with_policy.py` harness or direct `python -m agentgate.proxy`).

2. **Shared test fixtures in `conftest.py`** that PR2 issues (#8, #10, #11, #15, #26) will reuse — eliminating fixture duplication and ensuring a consistent test vocabulary across the entire test suite.

This is a consolidation issue, not a feature issue. No new modules. No new data models. The goal is: make the existing code thoroughly tested for PR1 scope, and lay the fixture foundation so PR2 issues don't waste time rebuilding test infrastructure.

---

## 2. Scope

### In scope

- 6 new integration tests in `tests/test_integration.py` that test scenarios not already covered by `test_proxy.py` or `test_proxy_policy.py`
- 4 shared fixtures added to `tests/conftest.py`: `sample_policy`, `minimal_policy`, `make_tool_call`, `compiled_policy_from_yaml`
- Verify the full `agentgate start --policy <file> -- <cmd>` path works via subprocess (CLI as entry point, not just the Python harness)
- Verify latency overhead is reasonable (< 50ms per call — not the final P1 target of 15ms, but a sanity check)

### Out of scope

- Testing against the real `@modelcontextprotocol/server-filesystem` via npx — the echo MCP server is sufficient for PR1 and avoids the npx cold-start flakiness. Real filesystem server testing is deferred to #15 (acceptance tests).
- Detector testing (PR2 — Issues #21–#26)
- `param_rule` evaluation testing (PR2 — Issue #8)
- `chain_rule` evaluation testing (PR2 — Issue #11)
- Audit log testing (PR2 — Issue #12)
- Any new source modules

---

## 3. What's Already Covered (Gap Analysis)

Before defining new tests, here's what the existing 63 tests already cover:

| Scenario | Covered by | Gap? |
|----------|-----------|------|
| Proxy spawns child, completes MCP handshake | `test_proxy.py::test_initialize_handshake` | None |
| `tools/list` returns tools through proxy | `test_proxy.py::test_tools_list` | None |
| `tools/call` passthrough (no policy) | `test_proxy.py::test_tool_call_passthrough` | None |
| Clean shutdown | `test_proxy.py::test_clean_shutdown` | None |
| Stderr passthrough | `test_proxy.py::test_stderr_passthrough` | None |
| Allowed tool passes through (with policy) | `test_proxy_policy.py::test_allowed_tool_passes_through` | None |
| Blocked tool returns error | `test_proxy_policy.py::test_blocked_tool_returns_error` | None |
| Tool not on allowlist blocked | `test_proxy_policy.py::test_tool_not_on_allowlist_blocked` | None |
| Non-tool-call messages pass through | `test_proxy_policy.py::test_non_tool_call_messages_pass_through` | None |
| No policy = passthrough | `test_proxy_policy.py::test_no_policy_means_passthrough` | None |
| Default block with no rules | `test_proxy_policy.py::test_default_block_with_no_rules` | None |
| Error response format | `test_proxy_policy.py::test_error_response_format` | None |
| Mixed allow/block decisions | `test_proxy_policy.py::test_multiple_calls_mixed_decisions` | None |
| Blocklist beats allowlist | `test_engine.py::test_blocklist_beats_allowlist` (unit) | **Yes — not integration-tested through proxy** |
| CLI `start` with valid policy (banner) | `test_cli.py::test_start_banner_output` | Partial — tests banner, not actual proxy relay |
| CLI `start` as entry point for tool calls | — | **Yes — never tested** |
| `agentgate.yaml.example` loads correctly | — | **Yes — golden path policy never loaded in tests** |
| Latency sanity check | — | **Yes — never measured** |
| Multiple sequential tool calls with policy | `test_proxy_policy.py::test_multiple_calls_mixed_decisions` | Partial — only 3 calls |

**Gaps to fill:**

1. Blocklist-beats-allowlist as an integration test through the live proxy
2. CLI `agentgate start` as the actual entry point (not the Python harness)
3. `agentgate.yaml.example` (the golden path policy) loads and works
4. Latency sanity check
5. Shared fixtures for PR2

---

## 4. Technical Decisions

### Decision 1: New test file `test_integration.py`, not additions to existing files

**Choice:** Create `tests/test_integration.py` for the new PR1 integration tests.

**Rationale:** `test_proxy.py` tests the proxy without policy (Issue #1 scope). `test_proxy_policy.py` tests proxy + policy wiring (Issue #5 scope). Issue #7 tests are PR1-level integration scenarios that don't fit cleanly in either. A separate file makes it clear these are the "PR1 graduation tests" — the final proof that PR1 is done.

### Decision 2: Echo server is sufficient — no npx/filesystem server

**Choice:** All Issue #7 tests use the existing echo MCP server (`tests/helpers/echo_mcp_server.py`).

**Rationale:** The echo server already speaks correct LSP-framed JSON-RPC and exercises the full proxy pipeline. Using the real filesystem server via npx adds a 10–30s cold-start penalty, an npm dependency, and flakiness from network issues. The echo server proves the proxy works. The real filesystem server proves it works with a specific MCP implementation — that's an acceptance test concern (Issue #15), not an integration test concern.

### Decision 3: CLI integration test uses `subprocess.run` with the installed `agentgate` binary

**Choice:** Test `agentgate start --policy <file> -- <echo_server_cmd>` via subprocess, send a tool call, read the response.

**Rationale:** This is the actual user-facing integration path. All previous proxy tests bypass the CLI and invoke `StdioProxy` directly (via `proxy_with_policy.py` harness or `python -m agentgate.proxy`). We need at least one test that exercises the real CLI entry point to confirm the full stack works as users will use it.

**Risk:** The installed `agentgate` binary must be in PATH. Handled the same way `test_cli.py` handles it — using the `.venv/bin/agentgate` path.

### Decision 4: Latency test measures wall-clock time for a tool call round-trip

**Choice:** Time the interval between sending a `tools/call` message and receiving the response, with and without policy, and assert the overhead is < 50ms.

**Rationale:** The MVP spec targets < 15ms median overhead (P1). 50ms is a generous upper bound for a sanity check — if we're above 50ms in a test with an in-process echo server, something is fundamentally wrong. The real latency measurement with p99 stats is PR3 evaluation work. This is just a smoke test.

### Decision 5: Fixtures use factory patterns, not static objects

**Choice:** `make_tool_call` is a factory function. `compiled_policy_from_yaml` is a factory that takes a YAML string.

**Rationale:** PR2 tests need to construct many different `ToolCall` and `CompiledPolicy` instances with varying parameters. Static fixtures force tests to mutate shared state or create their own objects anyway. Factories are composable and explicit.

---

## 5. Shared Fixtures

### 5.1 `make_tool_call` — Factory for `ToolCall` instances

```python
@pytest.fixture()
def make_tool_call():
    """Factory: build a ToolCall with defaults."""
    def _make(
        tool_name: str = "echo_tool",
        arguments: dict | None = None,
        call_id: int | str | None = 1,
    ) -> ToolCall:
        return ToolCall(
            tool_name=tool_name,
            arguments=arguments or {},
            call_id=call_id,
        )
    return _make
```

**Used by:** #8 (param_rule tests need varied `arguments`), #11 (chain detection needs sequences of calls), #15 (acceptance tests), #26 (detector wiring).

### 5.2 `compiled_policy_from_yaml` — Factory that compiles a YAML string into `CompiledPolicy`

```python
@pytest.fixture()
def compiled_policy_from_yaml(tmp_path):
    """Factory: compile a YAML policy string into a CompiledPolicy."""
    def _compile(yaml_content: str) -> CompiledPolicy:
        policy_path = tmp_path / "test_policy.yaml"
        policy_path.write_text(yaml_content, encoding="utf-8")
        return load_and_compile(str(policy_path))
    return _compile
```

**Used by:** #8 (param_rule tests need policies with param rules), #11 (chain rule tests), #15 (acceptance tests with full policies), #26 (detector wiring tests with detector toggles).

### 5.3 `sample_policy` — The golden path `agentgate.yaml.example` loaded as `CompiledPolicy`

```python
@pytest.fixture()
def sample_policy() -> CompiledPolicy:
    """Load agentgate.yaml.example as a CompiledPolicy. Proves the golden path config is valid."""
    example_path = Path(__file__).parent.parent / "agentgate.yaml.example"
    return load_and_compile(str(example_path))
```

**Used by:** #15 (acceptance tests use the golden path policy), #17 (evaluation scenarios reference it).

### 5.4 `minimal_policy` — Detectors-only, no custom rules, default allow

```python
@pytest.fixture()
def minimal_policy() -> CompiledPolicy:
    """A minimal allow-all policy with no rules. Default decision: allow."""
    config = PolicyConfig(version="0.1")
    return CompiledPolicy(config=config, regexes={})
```

**Used by:** #26 (detector wiring tests need a policy with no rules to isolate detector behavior), #15 (AT-4 benign passthrough needs a permissive policy).

---

## 6. Test Plan

**File:** `tests/test_integration.py`

All tests are integration tests. They spawn proxy subprocesses and communicate via stdin/stdout.

### Test 1: `test_blocklist_overrides_allowlist_through_proxy`

**Purpose:** Verify that the blocklist-beats-allowlist precedence rule works end-to-end through the live proxy, not just in the unit-tested engine.

**Setup:** Policy with `tool_allow: [echo_tool, blocked_tool]` and `tool_block: [blocked_tool]`.  
**Action:** Initialize. Send `tools/call` for `blocked_tool` (id=10).  
**Assert:** Response has `error`, `error["data"]["matched_rule"]` is the block rule name. The tool did NOT reach the echo server (it would have returned a result if it did).

**Why not already covered:** `test_proxy_policy.py::test_multiple_calls_mixed_decisions` uses `MIXED_POLICY` which is the same shape, but that test focuses on interleaving — it doesn't assert the specific precedence semantic (that the block rule name is what matches, not the allow rule). This test is explicit about the precedence contract.

### Test 2: `test_cli_start_as_entry_point`

**Purpose:** Verify the full `agentgate start --policy <file> -- <cmd>` CLI path works for real tool calls, not just banner output.

**Setup:** Write `ALLOW_ECHO` policy to a temp file. Spawn `agentgate start --policy <tmpfile> -- python <echo_server_path>` as a subprocess.  
**Action:** Initialize. Send `tools/call` for `echo_tool`.  
**Assert:** Response has `result` with echoed content. Proxy was started via the actual CLI binary.

**Why not already covered:** `test_cli.py` tests validate argument handling, banner output, and error cases. None of them send MCP messages through the CLI-started proxy. `test_proxy_policy.py` tests use the `proxy_with_policy.py` harness, not the CLI.

### Test 3: `test_golden_path_policy_loads_and_evaluates`

**Purpose:** Verify `agentgate.yaml.example` is syntactically valid, loads without error, compiles all regexes, and produces sane evaluation results.

**Setup:** Load `agentgate.yaml.example` via `load_and_compile()`.  
**Action:** Evaluate several `ToolCall` instances against it:
  - `read_file` (on allowlist) → expect allow
  - `delete_file` (on blocklist) → expect block
  - `unknown_tool` (not on allowlist) → expect block  
**Assert:** All three decisions are correct. The `CompiledPolicy` has the expected number of compiled regexes (2: one for `internal-email-only` param_rule `matches` op, plus chain rule regexes).

**Why not already covered:** `test_policy.py::test_load_full_policy` loads the golden path YAML shape but as an inline string. No test loads the actual `agentgate.yaml.example` file from disk, and no test evaluates the engine against it. This is the "does the shipped example actually work?" sanity test.

### Test 4: `test_latency_overhead_sanity_check`

**Purpose:** Smoke-test that the proxy + policy evaluation overhead is not catastrophically slow.

**Setup:** Policy = `ALLOW_ECHO`. Spawn proxy.  
**Action:** Initialize. Send 10 consecutive `tools/call` messages for `echo_tool`. Measure wall-clock time for each send-to-receive round trip.  
**Assert:** Median round-trip time < 200ms. Overhead vs no-policy proxy < 50ms.

**Why this threshold:** The echo server responds instantly. The proxy adds parsing + engine evaluation + re-framing. In a test environment with subprocess pipes, 200ms total is generous. The 50ms overhead ceiling is well above the 15ms MVP target but catches regressions like "accidentally calling `re.compile` on every request" or "blocking on a synchronous file read in the hot path."

**Note:** This is not the real performance evaluation (that's PR3). This is a "did we obviously break something?" guard rail.

### Test 5: `test_rapid_sequential_calls_no_corruption`

**Purpose:** Stress-test the proxy with rapid sequential tool calls to verify no message corruption or ordering issues.

**Setup:** Policy = `ALLOW_ECHO`. Spawn proxy.  
**Action:** Initialize. Send 20 consecutive `tools/call` messages with unique `id` values (100–119) and unique `arguments.message` values.  
**Assert:** All 20 responses received. Each response `id` matches a sent request `id`. Each response contains the correct echoed message. No responses missing, duplicated, or swapped.

**Why not already covered:** `test_proxy_policy.py::test_multiple_calls_mixed_decisions` sends 3 calls. 20 calls tests that the proxy handles rapid sequential I/O without buffer corruption or message interleaving bugs.

### Test 6: `test_sample_policy_fixture_is_valid`

**Purpose:** Verify the `sample_policy` fixture works and the golden path example has the expected structure.

**Setup:** Use the `sample_policy` fixture.  
**Assert:**
  - `sample_policy.config.version == "0.1"`
  - `sample_policy.config.settings.default_decision == "allow"`
  - `len(sample_policy.config.policies) == 5`
  - `len(sample_policy.regexes) >= 2` (at least the param_rule regex and chain_rule regexes)

**Why this exists:** If the example YAML drifts out of sync with the models (e.g., someone edits the example but not the Pydantic schema), this test catches it. It also validates that the `sample_policy` fixture works before PR2 tests depend on it.

---

## 7. Changes to `conftest.py`

### Current state

`conftest.py` currently contains:
- `echo_server_cmd` fixture
- `proxy_process` fixture (proxy without policy)
- `proxy_with_policy` fixture (factory, spawns proxy with policy via env var harness)

### Additions

| Fixture | Type | Description |
|---------|------|-------------|
| `make_tool_call` | Factory | Returns `ToolCall` from `(tool_name, arguments, call_id)` |
| `compiled_policy_from_yaml` | Factory | Compiles YAML string → `CompiledPolicy` via temp file |
| `sample_policy` | Instance | Loads `agentgate.yaml.example` → `CompiledPolicy` |
| `minimal_policy` | Instance | Empty-rules policy with `default_decision: allow` |

### No changes to existing fixtures

`echo_server_cmd`, `proxy_process`, and `proxy_with_policy` are unchanged. Existing tests (`test_proxy.py`, `test_proxy_policy.py`, `test_cli.py`) continue to work without modification.

---

## 8. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | Blocklist-beats-allowlist works through the live proxy (not just unit engine) | Test 1 |
| AC-2 | `agentgate start` CLI as entry point correctly proxies tool calls with policy enforcement | Test 2 |
| AC-3 | `agentgate.yaml.example` loads, compiles, and evaluates correctly | Tests 3, 6 |
| AC-4 | Proxy overhead < 50ms per call in test environment | Test 4 |
| AC-5 | No message corruption or ordering bugs under rapid sequential load | Test 5 |
| AC-6 | Shared fixtures (`make_tool_call`, `compiled_policy_from_yaml`, `sample_policy`, `minimal_policy`) are importable and work | Test 6 + successful import by test file |
| AC-7 | All existing tests (63) still pass | `pytest` full suite |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **CLI binary path differs across environments** | Medium | Medium | Use the same `VENV_AGENTGATE` pattern from `test_cli.py`. If binary not found, skip test with `pytest.mark.skipif`. |
| **Latency test is flaky under CI load** | Medium | Low | Use generous threshold (200ms total, 50ms overhead). If flaky, increase thresholds or mark as `pytest.mark.slow`. This is a smoke test, not a benchmark. |
| **`agentgate.yaml.example` path is fragile** | Low | Low | Use `Path(__file__).parent.parent / "agentgate.yaml.example"` which is relative to the test file. The file is committed to repo root — stable. |
| **20-call stress test is slow** | Low | Low | 20 calls at ~50ms each = ~1s. Acceptable for integration tests. |
| **Existing fixtures break** | Very Low | High | No existing fixtures are modified. Only new fixtures are added. Run existing tests first to confirm. |

---

## 10. What These Fixtures Enable in PR2

The shared fixtures are specifically designed for downstream issue needs:

| PR2 Issue | Fixture needed | How it's used |
|-----------|---------------|---------------|
| #8 (param_rule) | `make_tool_call`, `compiled_policy_from_yaml` | Build calls with specific arguments, compile policies with param_rules, evaluate |
| #10 (session store) | `make_tool_call` | Create sequences of tool calls to push into the session deque |
| #11 (chain detection) | `make_tool_call`, `compiled_policy_from_yaml`, `sample_policy` | Build call sequences, test chain rules from the golden path policy |
| #15 (acceptance tests) | `sample_policy`, `make_tool_call`, `proxy_with_policy` | AT-1 through AT-5 use the golden path policy with specific attack tool calls |
| #21–#25 (detectors) | `make_tool_call` | Build tool calls with attack payloads (SQL injection strings, path traversal paths, etc.) |
| #26 (wire detectors) | `minimal_policy`, `make_tool_call` | Test detector pipeline with a no-rules policy to isolate detector behavior |

---

## 11. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `tests/test_integration.py` | **New** | 6 integration tests |
| `tests/conftest.py` | **Modified** | 4 new fixtures added (no existing fixtures changed) |

No source files are touched. No changes to `proxy.py`, `parser.py`, `policy.py`, `engine.py`, `cli.py`, or `models.py`.

---

## 12. Definition of Done

- [ ] `tests/test_integration.py` contains 6 integration tests, all passing
- [ ] Blocklist-beats-allowlist verified through live proxy subprocess (not just unit engine)
- [ ] `agentgate start` CLI verified as working entry point for proxied tool calls
- [ ] `agentgate.yaml.example` verified as loadable, compilable, and evaluable
- [ ] Latency overhead smoke-tested (< 50ms overhead per call)
- [ ] No message corruption under 20 rapid sequential calls
- [ ] `conftest.py` contains 4 new shared fixtures: `make_tool_call`, `compiled_policy_from_yaml`, `sample_policy`, `minimal_policy`
- [ ] All existing tests (63) still pass
- [ ] Total test count: 69+ (63 existing + 6 integration = 69)
- [ ] All new fixtures are importable by both `test_integration.py` and future PR2 test files