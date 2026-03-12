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
| `parser.py` | JSON-RPC message parsing (stub) |
| `policy.py` | YAML policy loader & regex compilation (stub) |
| `engine.py` | Top-to-bottom rule evaluation (stub) |
| `proxy.py` | Stdio MCP proxy — spawns child process, intercepts calls (stub) |
| `session.py` | Sliding-window deque of recent calls for chain detection (stub) |
| `audit.py` | Async SQLite writer with SHA-256 hash chaining (stub) |
| `cli.py` | Click CLI: `init`, `start`, `logs` commands (stubs) |

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

- `src/agentgate/models.py` — Core Pydantic contracts (the only fully implemented module)
- `agentgate.yaml.example` — Golden-path policy demonstrating all features
- `docs/mvp-spec.md` — Frozen MVP specification with success criteria and evaluation plan
- `tests/test_models.py` — 11 model validation tests (only real test file)
- `.github/CONTRIBUTING.md` — Dev setup and PR process

## Code Style

- **Ruff** for linting and formatting, 100 char line limit
- Type hints on all public functions
- Pydantic v2 models for all data contracts between modules
