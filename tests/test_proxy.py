"""Integration tests for the stdio MCP proxy."""

from __future__ import annotations

import subprocess

from tests.helpers.mcp_client import do_initialize, read_message, send_message


class TestProxyHandshake:
    """AC-1 & AC-2: Proxy spawns child and completes MCP handshake."""

    def test_initialize_handshake(self, proxy_process: subprocess.Popen) -> None:
        response = do_initialize(proxy_process)
        assert response["id"] == 1
        assert "result" in response
        assert "protocolVersion" in response["result"]
        assert "capabilities" in response["result"]


class TestProxyRelay:
    """AC-3 & AC-4: Proxy relays tools/list and tools/call correctly."""

    def test_tools_list(self, proxy_process: subprocess.Popen) -> None:
        do_initialize(proxy_process)
        send_message(
            proxy_process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
            },
        )
        response = read_message(proxy_process)
        assert response["id"] == 2
        tools = response["result"]["tools"]
        assert isinstance(tools, list)
        tool_names = [t["name"] for t in tools]
        assert "echo_tool" in tool_names

    def test_tool_call_passthrough(self, proxy_process: subprocess.Popen) -> None:
        do_initialize(proxy_process)
        send_message(
            proxy_process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "echo_tool",
                    "arguments": {"message": "hello from test"},
                },
            },
        )
        response = read_message(proxy_process)
        assert response["id"] == 3
        content = response["result"]["content"]
        assert any("hello from test" in c["text"] for c in content)


class TestProxyLifecycle:
    """AC-5: Proxy exits cleanly when agent disconnects."""

    def test_clean_shutdown(self, proxy_process: subprocess.Popen) -> None:
        do_initialize(proxy_process)
        proxy_process.stdin.close()
        exit_code = proxy_process.wait(timeout=5)
        assert exit_code == 0
        assert proxy_process.poll() is not None

    def test_stderr_passthrough(self, proxy_process: subprocess.Popen) -> None:
        # The echo server writes STDERR_MARKER to stderr on startup.
        do_initialize(proxy_process)

        # Close stdin to trigger shutdown so stderr gets flushed
        proxy_process.stdin.close()
        proxy_process.wait(timeout=5)

        stderr_output = proxy_process.stderr.read().decode("utf-8", errors="replace")
        assert "STDERR_MARKER_12345" in stderr_output
