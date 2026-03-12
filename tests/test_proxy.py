"""Integration tests for the stdio MCP proxy."""

from __future__ import annotations

import json
import subprocess


def send_message(proc: subprocess.Popen, payload: dict) -> None:
    """Send an LSP-framed JSON-RPC message to a subprocess's stdin."""
    body = json.dumps(payload).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    proc.stdin.write(header + body)
    proc.stdin.flush()


def read_message(proc: subprocess.Popen) -> dict:
    """Read one LSP-framed JSON-RPC message from a subprocess's stdout."""
    content_length = None
    while True:
        line = proc.stdout.readline()
        if not line:
            raise EOFError("Unexpected EOF reading message headers")
        line_str = line.decode("ascii", errors="replace").strip()
        if not line_str:
            break
        if line_str.lower().startswith("content-length:"):
            content_length = int(line_str.split(":", 1)[1].strip())

    if content_length is None:
        raise ValueError("No Content-Length header found")

    payload = proc.stdout.read(content_length)
    if len(payload) < content_length:
        raise EOFError("Unexpected EOF reading message payload")

    return json.loads(payload)


def do_initialize(proc: subprocess.Popen) -> dict:
    """Send initialize + initialized handshake. Returns the initialize response."""
    send_message(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1.0"},
            },
        },
    )
    response = read_message(proc)
    # Send initialized notification (no id = notification)
    send_message(
        proc,
        {
            "jsonrpc": "2.0",
            "method": "initialized",
        },
    )
    return response


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
