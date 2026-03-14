# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AgentGate is a Python tool-call policy engine and runtime proxy for AI agents. It intercepts MCP tool calls and enforces declarative YAML security policies — acting as a firewall between agents and their tools.

**Status:** MVP v0.1.0 (early development — most modules are stubs)
**Python:** >= 3.10 | **Build:** Hatchling | **License:** Apache-2.0

## Commands

Always use the project venv (`.venv/`) via `uv` for running tests, linting, and any Python commands. Never install or run tools in the system Python.

```bash
# Setup
uv venv
uv pip install -e ".[dev]"

# Test (always inside venv)
uv run pytest                         # run all tests
uv run pytest tests/test_models.py    # run a single test file
uv run pytest -k "test_name"          # run a single test by name

# Lint & Format (always inside venv)
uv run ruff check src/ tests/         # lint
uv run ruff format src/ tests/        # format
```

## Architecture

```
Agent → Parser → Detectors → Rule Engine → Decision (allow/block) → Tool Server
                                  ↓ if blocked
                            Audit Log (SQLite, hash-chained)
```

### Core Pipeline (`src/agentgate/`)

| Module | Role |
|--------|------|
| `models.py` | Pydantic data contracts (ToolCall, Decision, PolicyConfig, rules) — **implemented** |
| `parser.py` | JSON-RPC message parsing (`ParsedMessage`, `parse_message()`, `build_error_response()`) — **implemented** |
| `policy.py` | YAML policy loader & regex compilation (`load_policy()`, `compile_regexes()`, `load_and_compile()`, `PolicyLoadError`, `CompiledPolicy`) — **implemented** |
| `engine.py` | Top-to-bottom rule evaluation (`evaluate()` — detectors, tool_block, tool_allow, param_rule, chain_rule, default decision) — **implemented** |
| `proxy.py` | Stdio MCP proxy — LSP-framed bidirectional relay with policy interception (`read_message`, `write_message`, `_intercepting_relay`, `StdioProxy`) — **implemented** |
| `session.py` | Sliding-window deque of recent calls for chain detection (`SessionEntry`, `SessionStore`) — **implemented** |
| `audit.py` | Background-thread SQLite writer with SHA-256 hash chaining (`AuditWriter`, `_compute_hash`, `verify_chain`) — **implemented** |
| `cli.py` | Click CLI: `init` (copies starter policy to cwd), `start` (hardened — env var override, `--verbose`, `--audit-db`, startup banner, error handling), `logs` (read-only SQLite query, JSON Lines output, `--tail`, `--session`, `--decision`, `--db`, `--verify` hash chain) — **implemented** |

### Detectors (`src/agentgate/detectors/`)

- `_util.py` — Shared `extract_strings()` helper: recursively walks dicts, lists (including nested lists), and extracts all `(key_path, string_value)` pairs — **implemented**
- `sql_injection.py` — Destructive SQL patterns (DROP, DELETE, UNION SELECT, tautologies, stacked queries) — **implemented**
- `path_traversal.py` — Traversal sequences (`../`, encoded variants), sensitive absolute paths, null byte injection — **implemented**
- `command_injection.py` — Shell metacharacters (`;`, `&&`, `|`, backticks, `$()`) with context-aware matching — **implemented**
- `ssrf.py` — Private/loopback/link-local/reserved IP detection in URLs and bare IPs via `ipaddress` stdlib — **implemented**
- `secrets.py` — AWS keys, GitHub tokens, PEM private keys, passwords, Slack/Stripe/Bearer tokens via exact-format regex — **implemented**
- `chain.py` — Sequential attack pattern matching: `evaluate_chain_rules()` scans session history for ordered multi-step tool-call sequences — **implemented**

### Policy Language (YAML)

Four rule types: `tool_allow`, `tool_block`, `param_rule`, `chain_rule`. See `agentgate.yaml.example` for complete syntax with all rule types demonstrated.

## Key Files

- `src/agentgate/models.py` — Core Pydantic contracts (fully implemented)
- `src/agentgate/parser.py` — JSON-RPC parser: classifies messages by kind, extracts `ToolCall` from `tools/call` requests (fully implemented)
- `src/agentgate/policy.py` — YAML policy loader: two-phase load (parse → compile), `PolicyLoadError` exception, `CompiledPolicy` dataclass with pre-compiled regex map (fully implemented)
- `src/agentgate/engine.py` — Rule engine: `evaluate()` checks detectors (Step 1), tool_block, tool_allow, param_rule (6 operators, negate, dot-notation), chain_rule (session history matching), and default decision with correct precedence (fully implemented)
- `src/agentgate/proxy.py` — Stdio proxy with policy interception: `_intercepting_relay` parses tool calls, evaluates against policy, blocks or forwards, logs decisions to audit writer (fully implemented)
- `agentgate.yaml.example` — Golden-path policy demonstrating all features
- `docs/mvp-spec.md` — Frozen MVP specification with success criteria and evaluation plan
- `tests/test_parser.py` — 12 parser unit tests (sync, no I/O)
- `tests/test_models.py` — 11 model validation tests
- `tests/test_policy.py` — 11 policy loader tests (sync, tmp_path I/O only)
- `tests/test_engine.py` — 17 rule engine tests (10 rule precedence + 4 detector integration + 3 chain rule; sync, no I/O)
- `tests/test_param_rule.py` — 26 param_rule tests (12 operator, 4 negate, 4 param resolution, 2 tool match, 4 precedence; sync, no I/O)
- `tests/test_proxy.py` — 5 integration tests for the stdio proxy
- `tests/test_proxy_policy.py` — 9 integration tests for proxy + policy engine wiring (allow, block, passthrough, error format, mixed decisions, detector blocking)
- `tests/test_integration.py` — 6 PR1 integration tests (blocklist precedence, CLI entry point, golden path policy, latency, stress, fixture validation)
- `tests/test_detectors/test_sql_injection.py` — 20 SQL injection detector tests (7 positive, 7 negative, 2 edge cases + 4 additional coverage; sync, no I/O)
- `tests/test_detectors/test_path_traversal.py` — 17 path traversal detector tests (8 positive, 7 negative, 2 edge cases; sync, no I/O)
- `tests/test_detectors/test_command_injection.py` — 17 command injection detector tests (8 positive, 7 negative, 2 edge cases; sync, no I/O)
- `tests/test_detectors/test_ssrf.py` — 17 SSRF detector tests (8 positive, 7 negative, 2 edge cases; sync, no I/O)
- `tests/test_detectors/test_secrets.py` — 19 secrets detector tests (8 positive, 7 negative, 2 edge cases + 2 additional coverage; sync, no I/O)
- `tests/test_detectors/test_registry.py` — 8 detector pipeline tests (run_all wiring, enable/disable, multi-detector; sync, no I/O)
- `tests/test_detectors/test_chain.py` — 15 chain detection tests (6 positive, 6 negative, 3 edge cases; sync, no I/O)
- `tests/test_audit.py` — 15 audit writer tests (table creation, field correctness, genesis hash, chain linking, determinism, verification, tampering, flush, idempotent close, resume, timestamps, key sorting, concurrency, latency; sync, tmp_path I/O)
- `tests/test_chain_integration.py` — 4 chain detection integration tests (AT-3 exfil blocking, benign sequence, param mismatch, read-only)
- `tests/test_session.py` — 12 session store unit tests (empty, record, ordering, eviction, clear, timestamps; sync, no I/O)
- `tests/test_cli.py` — 7 CLI tests (CliRunner for arg validation, subprocess for banner/error handling)
- `tests/test_cli_init.py` — 3 CLI init tests (happy path, overwrite refusal, valid policy; CliRunner, tmp_path)
- `tests/test_cli_logs.py` — 13 CLI logs tests (query filters, tail, combined filters, JSON Lines output, arguments parsing, null fields, verify intact/broken, db option, error cases; CliRunner, tmp_path I/O)
- `tests/conftest.py` — Shared fixtures: `echo_server_cmd`, `proxy_process`, `proxy_with_policy`, `make_tool_call`, `compiled_policy_from_yaml`, `sample_policy`, `minimal_policy`
- `tests/helpers/echo_mcp_server.py` — Minimal MCP server for proxy tests (no Node.js dependency)
- `tests/helpers/mcp_client.py` — Shared test helpers (`send_message`, `read_message`, `do_initialize`)
- `tests/helpers/proxy_with_policy.py` — Test harness for spawning proxy with a policy via env var
- `.github/CONTRIBUTING.md` — Dev setup and PR process

## Code Style

- **Ruff** for linting and formatting, 100 char line limit
- Type hints on all public functions
- Pydantic v2 models for all data contracts between modules
