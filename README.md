# AgentGate

**The firewall for what AI agents *do*, not what they say.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

AgentGate is an open-source tool-call policy engine for AI agents. It sits between your agent and its tools, intercepts every tool call, and enforces declarative policies that control what the agent is allowed to do.

## The Problem

Agent frameworks make it easy to give AI agents tools. They make it impossible to constrain how those tools are used. An agent tricked by prompt injection can read your SSH keys, email them to an attacker, and delete the evidence — and no framework will stop it.

AgentGate enforces tool-call-level policy deterministically — blocking unauthorized tool calls, dangerous parameters, known attack patterns, and unsafe tool-call sequences before they execute.

## How It Works

AgentGate is a transparent MCP proxy. It wraps your MCP server, intercepts tool calls, evaluates them against your policy, and blocks anything that violates it.

```
┌───────────────────────────────────────────────────────┐
│                    agentgate CLI                       │
│  init │ start │ logs                                   │
└────┬──────────┬───────────────────────────────────────┘
     │          │
     │   ┌──────▼────────────────────────────────────┐
     │   │           PROXY (stdio wrapper)            │
     │   │                                            │
     │   │  ┌──────────────────────────────────────┐  │
     │   │  │        REQUEST PARSER                 │  │
     │   │  │  JSON-RPC → tool_name + arguments     │  │
     │   │  └──────────┬───────────────────────────┘  │
     │   │             │                               │
     │   │  ┌──────────▼───────────────────────────┐  │
     │   │  │      DETECTOR PIPELINE               │  │
     │   │  │  sql_injection │ path_traversal       │  │
     │   │  │  command_injection │ ssrf_private_ip   │  │
     │   │  │  secrets_in_params                     │  │
     │   │  └──────────┬───────────────────────────┘  │
     │   │             │                               │
     │   │  ┌──────────▼───────────────────────────┐  │
     │   │  │         RULE ENGINE                   │  │
     │   │  │  tool_allow → tool_block →            │  │
     │   │  │  param_rule → chain_rule → default    │  │
     │   │  └──────────┬───────────────────────────┘  │
     │   │             │                               │
     │   │        allow │ block                        │
     │   │             │                               │
     │   │  ┌──────────▼──────┐  ┌─────────────────┐  │
     │   │  │  Forward to MCP │  │  Return error    │  │
     │   │  │  server child   │  │  to agent        │  │
     │   │  └─────────────────┘  └─────────────────┘  │
     │   └────────────────────────────────────────────┘
     │
     │   ┌────────────────────┐
     └──▶│  POLICY LOADER     │
         │  agentgate.yaml    │
         └────────────────────┘
```

## Quick Start

> AgentGate is in early development. Install from source during the MVP phase.

```bash
# Install from source
git clone https://github.com/YOUR_USERNAME/agentgate.git
cd agentgate
pip install -e .

# Generate a starter policy
agentgate init

# Start the proxy wrapping an MCP server
agentgate start -- npx -y @modelcontextprotocol/server-filesystem /data
```

Configure your MCP client to use AgentGate as the command:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentgate",
      "args": ["start", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    }
  }
}
```

## Policy Example

```yaml
version: "0.1"

settings:
  default_decision: allow

detectors:
  sql_injection: true
  path_traversal: true
  command_injection: true
  ssrf_private_ip: true
  secrets_in_params: true

policies:
  - name: sandboxed-files
    type: param_rule
    match:
      tool: read_file
    check:
      param: path
      op: starts_with
      value: "/data/workspace/"
      negate: true
    message: "File access restricted to /data/workspace/"

  - name: block-exfil-after-sensitive-read
    type: chain_rule
    window: 5
    steps:
      - tool: read_file
        output_matches: "BEGIN.*PRIVATE KEY|password|api[_-]?key"
      - tool: send_email
        param_matches:
          to: "^(?!.*@mycompany\\.com$).*$"
    message: "Blocked: sending email after reading sensitive data"
```

See [`agentgate.yaml.example`](agentgate.yaml.example) for the full golden path demo policy.

## What It Catches

AgentGate includes built-in detectors for the most common tool-misuse attacks:

- **Path traversal** — `../`, absolute paths outside allowed directories, sensitive file access
- **Credential exfiltration** — AWS keys, GitHub tokens, private keys, passwords in tool parameters
- **SQL injection** — destructive SQL patterns (DROP, DELETE, UNION SELECT) in string parameters
- **Command injection** — shell metacharacters (`;`, `&&`, `|`, backticks) in string parameters
- **SSRF** — private, loopback, link-local, and cloud metadata IPs in URL parameters
- **Exfiltration chains** — read sensitive data then send to external endpoint (sequential detection)

## Evaluation Results

> Coming soon. Evaluation harness and published metrics are planned for v0.1.

## Comparison

| Feature | AgentGate | Invariant (Snyk) | Pipelock | AgentGateway (LF) |
|---------|-----------|-------------------|----------|-------------------|
| Open source | Apache-2.0 | Frozen | Apache-2.0 | Apache-2.0 |
| Policy language | YAML DSL | Python DSL | — | Cedar/OPA |
| Chain detection | Planned | Yes | No | No |
| Python-native | Yes | Yes | No (Go) | No (Rust) |
| Active development | Yes | No (acquired) | Solo | Yes |
| Published eval metrics | Planned | No | No | No |

## Documentation

- [MVP Specification](docs/mvp-spec.md)

> Additional documentation (policy language reference, detector descriptions, architecture overview) will be added as features are implemented.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
```

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details.

## License

Apache-2.0 — see [LICENSE](LICENSE).
