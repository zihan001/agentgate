"""Integration tests for proxy + policy engine wiring (Issue #5)."""

from __future__ import annotations

import subprocess

from tests.helpers.mcp_client import do_initialize, read_message, send_message

# ---------------------------------------------------------------------------
# Policy YAML snippets
# ---------------------------------------------------------------------------

ALLOW_ECHO = """\
version: "0.1"
policies:
  - name: allow-echo
    type: tool_allow
    tools:
      - echo_tool
"""

BLOCK_ECHO = """\
version: "0.1"
policies:
  - name: block-echo
    type: tool_block
    tools:
      - echo_tool
"""

ALLOW_OTHER_ONLY = """\
version: "0.1"
policies:
  - name: allow-other
    type: tool_allow
    tools:
      - other_tool
"""

DEFAULT_BLOCK = """\
version: "0.1"
settings:
  default_decision: block
"""

MIXED_POLICY = """\
version: "0.1"
policies:
  - name: allow-tools
    type: tool_allow
    tools:
      - echo_tool
      - blocked_tool
  - name: block-dangerous
    type: tool_block
    tools:
      - blocked_tool
"""


def _tool_call_msg(tool_name: str, msg_id: int, arguments: dict | None = None) -> dict:
    """Build a tools/call JSON-RPC request."""
    params: dict = {"name": tool_name}
    if arguments is not None:
        params["arguments"] = arguments
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": params,
    }


class TestAllowedTool:
    """Test 1: Allowed tool calls pass through to MCP server."""

    def test_allowed_tool_passes_through(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(ALLOW_ECHO)
        do_initialize(proc)
        send_message(proc, _tool_call_msg("echo_tool", 2, {"message": "hello"}))
        response = read_message(proc)
        assert response["id"] == 2
        assert "result" in response
        assert "error" not in response
        content = response["result"]["content"]
        assert any("hello" in c["text"] for c in content)


class TestBlockedTool:
    """Test 2: Blocked tool calls return JSON-RPC error."""

    def test_blocked_tool_returns_error(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(BLOCK_ECHO)
        do_initialize(proc)
        send_message(proc, _tool_call_msg("echo_tool", 2))
        response = read_message(proc)
        assert "error" in response
        assert "result" not in response
        assert response["error"]["code"] == -32600
        assert response["error"]["message"] == "Tool call blocked by policy"
        assert response["error"]["data"]["matched_rule"] == "block-echo"
        assert "blocked" in response["error"]["data"]["message"].lower()


class TestAllowlistMiss:
    """Test 3: Tool not on allowlist is blocked."""

    def test_tool_not_on_allowlist_blocked(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(ALLOW_OTHER_ONLY)
        do_initialize(proc)
        send_message(proc, _tool_call_msg("echo_tool", 2))
        response = read_message(proc)
        assert "error" in response
        assert "not on the allowlist" in response["error"]["data"]["message"].lower()


class TestNonToolCallPassthrough:
    """Test 4: Non-tools/call messages pass through regardless of policy."""

    def test_non_tool_call_messages_pass_through(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(BLOCK_ECHO)
        # initialize
        response = do_initialize(proc)
        assert "result" in response
        assert "protocolVersion" in response["result"]

        # tools/list
        send_message(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        response = read_message(proc)
        assert "result" in response
        assert isinstance(response["result"]["tools"], list)


class TestNoPolicy:
    """Test 5: No policy means full passthrough (backward compatible)."""

    def test_no_policy_means_passthrough(self, proxy_process: subprocess.Popen) -> None:
        do_initialize(proxy_process)
        send_message(proxy_process, _tool_call_msg("echo_tool", 2, {"message": "passthrough"}))
        response = read_message(proxy_process)
        assert "result" in response
        content = response["result"]["content"]
        assert any("passthrough" in c["text"] for c in content)


class TestDefaultBlock:
    """Test 6: Default decision = block with no rules blocks everything."""

    def test_default_block_with_no_rules(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(DEFAULT_BLOCK)
        do_initialize(proc)
        send_message(proc, _tool_call_msg("echo_tool", 2))
        response = read_message(proc)
        assert "error" in response


class TestErrorFormat:
    """Test 7: Full JSON-RPC error response structure validation."""

    def test_error_response_format(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(BLOCK_ECHO)
        do_initialize(proc)
        send_message(proc, _tool_call_msg("echo_tool", 42))
        response = read_message(proc)

        assert response["id"] == 42
        assert response["jsonrpc"] == "2.0"
        assert response["error"]["code"] == -32600
        assert response["error"]["message"] == "Tool call blocked by policy"
        assert isinstance(response["error"]["data"], dict)
        assert response["error"]["data"]["matched_rule"] == "block-echo"
        assert response["error"]["data"]["matched_detector"] is None
        assert isinstance(response["error"]["data"]["message"], str)
        assert len(response["error"]["data"]["message"]) > 0


class TestMixedDecisions:
    """Test 8: Interleaved allow/block decisions without state corruption."""

    def test_multiple_calls_mixed_decisions(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(MIXED_POLICY)
        do_initialize(proc)

        # Call 1: echo_tool (allowed)
        send_message(proc, _tool_call_msg("echo_tool", 10, {"message": "ok"}))
        r1 = read_message(proc)
        assert r1["id"] == 10
        assert "result" in r1

        # Call 2: blocked_tool (blocked)
        send_message(proc, _tool_call_msg("blocked_tool", 11))
        r2 = read_message(proc)
        assert r2["id"] == 11
        assert "error" in r2

        # Call 3: echo_tool again (still allowed)
        send_message(proc, _tool_call_msg("echo_tool", 12, {"message": "still ok"}))
        r3 = read_message(proc)
        assert r3["id"] == 12
        assert "result" in r3
