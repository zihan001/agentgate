# Examples

This directory will contain runnable examples for AgentGate.

## Planned files

- `demo_agent.py` — Golden path demo: a LangChain agent with filesystem and email tools, showing AgentGate blocking an indirect prompt injection attack
- `email_mcp_server.py` — Minimal MCP server (~50 lines) that simulates `send_email`
- `policies/minimal.yaml` — Detectors only, no custom rules
- `policies/restrictive.yaml` — Full sandbox + email allowlist + chain rules
- `policies/permissive.yaml` — Log-only (default allow, all detectors on)
