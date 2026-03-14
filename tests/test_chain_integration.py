"""Integration tests for chain detection through the proxy (Issue #11, AT-3)."""

from __future__ import annotations

from tests.helpers.mcp_client import do_initialize, read_message, send_message

# ---------------------------------------------------------------------------
# Policy YAML — uses SENSITIVE_MARKER to avoid triggering built-in detectors
# ---------------------------------------------------------------------------

CHAIN_POLICY = """\
version: "0.1"
settings:
  default_decision: allow
detectors:
  secrets_in_params: false
policies:
  - name: block-exfil
    type: chain_rule
    window: 5
    steps:
      - tool: echo_tool
        output_matches: "SENSITIVE_MARKER"
      - tool: echo_tool
        param_matches:
          action: "^send"
    message: "Blocked: exfil after sensitive read"
"""


def _tool_call_msg(tool_name: str, msg_id: int, arguments: dict | None = None) -> dict:
    params = {"name": tool_name}
    if arguments is not None:
        params["arguments"] = arguments
    else:
        params["arguments"] = {}
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": params,
    }


class TestChainBlocksExfilThroughProxy:
    """AT-3: read with sensitive response → send to external → BLOCKED."""

    def test_chain_blocks_exfil(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(CHAIN_POLICY)
        do_initialize(proc)

        # Step 1: Send a tool call that returns sensitive data
        send_message(
            proc,
            _tool_call_msg(
                "echo_tool", 2, {"_mock_response": "data contains SENSITIVE_MARKER here"}
            ),
        )
        response = read_message(proc)
        assert "result" in response
        assert response["id"] == 2

        # Step 2: Send a tool call that should be blocked by chain rule
        send_message(
            proc,
            _tool_call_msg("echo_tool", 3, {"action": "send_external"}),
        )
        response = read_message(proc)
        assert "error" in response
        assert response["error"]["code"] == -32600
        assert response["error"]["data"]["matched_rule"] == "block-exfil"


class TestChainAllowsBenignSequence:
    """Benign response → send → both allowed (no false positive)."""

    def test_benign_sequence_allowed(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(CHAIN_POLICY)
        do_initialize(proc)

        # Step 1: Send a tool call with benign response
        send_message(
            proc,
            _tool_call_msg(
                "echo_tool", 2, {"_mock_response": "nothing special here"}
            ),
        )
        response = read_message(proc)
        assert "result" in response

        # Step 2: Send action — should be allowed (output_matches didn't match)
        send_message(
            proc,
            _tool_call_msg("echo_tool", 3, {"action": "send_external"}),
        )
        response = read_message(proc)
        assert "result" in response
        assert "error" not in response


class TestChainAllowsWhenParamMismatch:
    """Sensitive response → non-matching param → allowed."""

    def test_param_mismatch_allowed(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(CHAIN_POLICY)
        do_initialize(proc)

        # Step 1: Sensitive response
        send_message(
            proc,
            _tool_call_msg(
                "echo_tool", 2, {"_mock_response": "SENSITIVE_MARKER data"}
            ),
        )
        response = read_message(proc)
        assert "result" in response

        # Step 2: action doesn't match ^send
        send_message(
            proc,
            _tool_call_msg("echo_tool", 3, {"action": "read_only"}),
        )
        response = read_message(proc)
        assert "result" in response
        assert "error" not in response


class TestChainNoFalsePositiveReadOnly:
    """Multiple sensitive reads without a send → all allowed."""

    def test_reads_only_all_allowed(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(CHAIN_POLICY)
        do_initialize(proc)

        for i in range(3):
            send_message(
                proc,
                _tool_call_msg(
                    "echo_tool", i + 2, {"_mock_response": "SENSITIVE_MARKER data"}
                ),
            )
            response = read_message(proc)
            assert "result" in response
            assert "error" not in response
