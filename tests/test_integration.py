"""PR1 integration tests — blocklist precedence, CLI entry point, golden path policy, latency, stress."""

from __future__ import annotations

import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

from agentgate.engine import evaluate
from agentgate.models import ToolCall
from agentgate.policy import CompiledPolicy, load_and_compile
from tests.helpers.mcp_client import do_initialize, read_message, send_message

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ECHO_SERVER_PATH = str(Path(__file__).parent / "helpers" / "echo_mcp_server.py")
EXAMPLE_POLICY_PATH = str(Path(__file__).parent.parent / "agentgate.yaml.example")
VENV_AGENTGATE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "agentgate"
)

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

BLOCKLIST_BEATS_ALLOWLIST = """\
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Test 1: Blocklist overrides allowlist through the live proxy
# ---------------------------------------------------------------------------


class TestBlocklistOverridesAllowlist:
    """Blocklist takes precedence over allowlist end-to-end through the proxy."""

    def test_blocklist_overrides_allowlist_through_proxy(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(BLOCKLIST_BEATS_ALLOWLIST)
        do_initialize(proc)

        send_message(proc, _tool_call_msg("blocked_tool", 10))
        response = read_message(proc)

        assert response["id"] == 10
        assert "error" in response
        assert "result" not in response
        assert response["error"]["data"]["matched_rule"] == "block-dangerous"
        assert "blocked" in response["error"]["data"]["message"].lower()


# ---------------------------------------------------------------------------
# Test 2: CLI `agentgate start` as real entry point
# ---------------------------------------------------------------------------


class TestCliStartAsEntryPoint:
    """Full agentgate start --policy <file> -- <cmd> path works for real tool calls."""

    def test_cli_start_as_entry_point(self, tmp_path) -> None:
        # Write policy to temp file
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(ALLOW_ECHO, encoding="utf-8")

        # Spawn via the installed CLI binary
        cmd = [
            VENV_AGENTGATE,
            "start",
            "--policy",
            str(policy_path),
            "--",
            sys.executable,
            ECHO_SERVER_PATH,
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(__file__).parent.parent),
        )

        try:
            do_initialize(proc)
            send_message(proc, _tool_call_msg("echo_tool", 2, {"message": "cli-test"}))
            response = read_message(proc)

            assert response["id"] == 2
            assert "result" in response
            assert "error" not in response
            content = response["result"]["content"]
            assert any("cli-test" in c["text"] for c in content)
        finally:
            if proc.poll() is None:
                proc.stdin.close()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()


# ---------------------------------------------------------------------------
# Test 3: Golden path policy loads and evaluates correctly
# ---------------------------------------------------------------------------


class TestGoldenPathPolicy:
    """agentgate.yaml.example loads, compiles, and evaluates with correct decisions."""

    def test_golden_path_policy_loads_and_evaluates(self) -> None:
        policy = load_and_compile(EXAMPLE_POLICY_PATH)

        # read_file is on allowlist → allow
        decision_allow = evaluate(
            ToolCall(tool_name="read_file", arguments={}, call_id=1), policy
        )
        assert decision_allow.action == "allow"

        # delete_file is on blocklist → block
        decision_block = evaluate(
            ToolCall(tool_name="delete_file", arguments={}, call_id=2), policy
        )
        assert decision_block.action == "block"
        assert decision_block.matched_rule == "no-destructive-ops"

        # unknown_tool is not on allowlist → block
        decision_unknown = evaluate(
            ToolCall(tool_name="unknown_tool", arguments={}, call_id=3), policy
        )
        assert decision_unknown.action == "block"

        # Verify compiled regexes exist (param_rule "matches" op + chain_rule patterns)
        assert len(policy.regexes) >= 2


# ---------------------------------------------------------------------------
# Test 4: Latency overhead sanity check
# ---------------------------------------------------------------------------


class TestLatencySanity:
    """Proxy + policy overhead is not catastrophically slow."""

    def test_latency_overhead_sanity_check(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(ALLOW_ECHO)
        do_initialize(proc)

        round_trips: list[float] = []
        for i in range(10):
            start = time.monotonic()
            send_message(proc, _tool_call_msg("echo_tool", 50 + i, {"message": f"latency-{i}"}))
            response = read_message(proc)
            elapsed = time.monotonic() - start
            round_trips.append(elapsed)
            assert response["id"] == 50 + i
            assert "result" in response

        median_ms = statistics.median(round_trips) * 1000
        assert median_ms < 200, f"Median round-trip {median_ms:.1f}ms exceeds 200ms threshold"


# ---------------------------------------------------------------------------
# Test 5: Rapid sequential calls — no corruption
# ---------------------------------------------------------------------------


class TestRapidSequentialCalls:
    """20 rapid sequential calls with no message corruption or ordering bugs."""

    def test_rapid_sequential_calls_no_corruption(self, proxy_with_policy) -> None:
        proc = proxy_with_policy(ALLOW_ECHO)
        do_initialize(proc)

        num_calls = 20
        sent_ids = list(range(100, 100 + num_calls))
        responses: dict[int, dict] = {}

        for msg_id in sent_ids:
            send_message(
                proc,
                _tool_call_msg("echo_tool", msg_id, {"message": f"msg-{msg_id}"}),
            )
            response = read_message(proc)
            responses[response["id"]] = response

        # All 20 responses received with correct ids
        assert len(responses) == num_calls
        assert set(responses.keys()) == set(sent_ids)

        # Each response has the correct echoed content
        for msg_id, response in responses.items():
            assert "result" in response, f"id={msg_id} missing result"
            assert "error" not in response, f"id={msg_id} has unexpected error"
            content_text = " ".join(c["text"] for c in response["result"]["content"])
            assert f"msg-{msg_id}" in content_text, (
                f"id={msg_id} echoed wrong content: {content_text}"
            )


# ---------------------------------------------------------------------------
# Test 6: sample_policy fixture validation
# ---------------------------------------------------------------------------


class TestSamplePolicyFixture:
    """Validate the sample_policy fixture loads agentgate.yaml.example correctly."""

    def test_sample_policy_fixture_is_valid(self, sample_policy: CompiledPolicy) -> None:
        assert sample_policy.config.version == "0.1"
        assert sample_policy.config.settings.default_decision == "allow"
        assert len(sample_policy.config.policies) == 5
        assert len(sample_policy.regexes) >= 2
