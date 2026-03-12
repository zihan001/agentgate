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
| `engine.py` | Top-to-bottom rule evaluation (`evaluate()` — tool_block, tool_allow, default decision) — **implemented** |
| `proxy.py` | Stdio MCP proxy — LSP-framed bidirectional relay with policy interception (`read_message`, `write_message`, `_intercepting_relay`, `StdioProxy`) — **implemented** |
| `session.py` | Sliding-window deque of recent calls for chain detection (stub) |
| `audit.py` | Async SQLite writer with SHA-256 hash chaining (stub) |
| `cli.py` | Click CLI: `init` (stub), `start` (hardened — env var override, `--verbose`, startup banner, error handling), `logs` (stub) — **implemented** |

### Detectors (`src/agentgate/detectors/`) — all stubs

- `path_traversal.py` — `../` and absolute path detection
- `sql_injection.py` — Destructive SQL patterns (DROP, DELETE, UNION)
- `command_injection.py` — Shell metacharacters (`;`, `&&`, `|`, backticks, `$()`)
- `ssrf.py` — Private/loopback IP detection
- `secrets.py` — AWS keys, tokens, passwords in params
- `chain.py` — Sequential attack pattern matching

### Policy Language (YAML)

Four rule types: `tool_allow`, `tool_block`, `param_rule`, `chain_rule`. See `agentgate.yaml.example` for complete syntax with all rule types demonstrated.

## Key Files

- `src/agentgate/models.py` — Core Pydantic contracts (fully implemented)
- `src/agentgate/parser.py` — JSON-RPC parser: classifies messages by kind, extracts `ToolCall` from `tools/call` requests (fully implemented)
- `src/agentgate/policy.py` — YAML policy loader: two-phase load (parse → compile), `PolicyLoadError` exception, `CompiledPolicy` dataclass with pre-compiled regex map (fully implemented)
- `src/agentgate/engine.py` — Rule engine: `evaluate()` checks tool_block, tool_allow, and default decision with correct precedence (fully implemented, steps 1/4/5 deferred)
- `src/agentgate/proxy.py` — Stdio proxy with policy interception: `_intercepting_relay` parses tool calls, evaluates against policy, blocks or forwards (fully implemented)
- `agentgate.yaml.example` — Golden-path policy demonstrating all features
- `docs/mvp-spec.md` — Frozen MVP specification with success criteria and evaluation plan
- `tests/test_parser.py` — 12 parser unit tests (sync, no I/O)
- `tests/test_models.py` — 11 model validation tests
- `tests/test_policy.py` — 10 policy loader tests (sync, tmp_path I/O only)
- `tests/test_engine.py` — 10 rule engine tests (sync, no I/O)
- `tests/test_proxy.py` — 5 integration tests for the stdio proxy
- `tests/test_proxy_policy.py` — 8 integration tests for proxy + policy engine wiring (allow, block, passthrough, error format, mixed decisions)
- `tests/test_integration.py` — 6 PR1 integration tests (blocklist precedence, CLI entry point, golden path policy, latency, stress, fixture validation)
- `tests/test_cli.py` — 7 CLI tests (CliRunner for arg validation, subprocess for banner/error handling)
- `tests/conftest.py` — Shared fixtures: `echo_server_cmd`, `proxy_process`, `proxy_with_policy`, `make_tool_call`, `compiled_policy_from_yaml`, `sample_policy`, `minimal_policy`
- `tests/helpers/echo_mcp_server.py` — Minimal MCP server for proxy tests (no Node.js dependency)
- `tests/helpers/mcp_client.py` — Shared test helpers (`send_message`, `read_message`, `do_initialize`)
- `tests/helpers/proxy_with_policy.py` — Test harness for spawning proxy with a policy via env var
- `.github/CONTRIBUTING.md` — Dev setup and PR process

## Code Style

- **Ruff** for linting and formatting, 100 char line limit
- Type hints on all public functions
- Pydantic v2 models for all data contracts between modules
