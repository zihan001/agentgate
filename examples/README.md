# Examples

Runnable examples for AgentGate.

## Files

- `demo_agent.py` — Scripted golden path demo: 5 tool calls evaluated against a security policy, showing AgentGate blocking path traversal and data exfiltration attacks
- `email_mcp_server.py` — Minimal MCP server that simulates `send_email(to, subject, body)` over LSP-framed JSON-RPC
- `policies/demo.yaml` — Demo policy exercising all 4 rule types (tool_allow, param_rule, chain_rule) plus all detectors
- `policies/minimal.yaml` — Detectors only, no custom rules (default allow)
- `policies/restrictive.yaml` — Full sandbox with default block
- `policies/permissive.yaml` — Log-only with default allow and all detectors

## Usage

```bash
# Run the scripted demo (no external dependencies)
python examples/demo_agent.py

# Disable colored output
python examples/demo_agent.py --no-color

# Run the email server through the proxy with a policy
agentgate start --policy examples/policies/demo.yaml \
  -- python examples/email_mcp_server.py
```
