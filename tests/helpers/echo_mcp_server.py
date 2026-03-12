"""Minimal MCP server for testing the stdio proxy.

Speaks LSP-framed JSON-RPC over stdin/stdout. Handles:
- initialize → responds with capabilities and protocol version
- initialized (notification) → ignored
- tools/list → responds with a single echo_tool
- tools/call → echoes back the arguments
- Writes STDERR_MARKER to stderr on startup for stderr passthrough tests.
- Exits cleanly on stdin EOF.
"""

from __future__ import annotations

import json
import sys


STDERR_MARKER = "STDERR_MARKER_12345"


def read_message() -> dict | None:
    """Read one LSP-framed message from stdin. Returns None on EOF."""
    content_length = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line_str = line.decode("ascii").strip()
        if not line_str:
            break
        if line_str.lower().startswith("content-length:"):
            content_length = int(line_str.split(":", 1)[1].strip())
    if content_length is None:
        return None
    payload = sys.stdin.buffer.read(content_length)
    if len(payload) < content_length:
        return None
    return json.loads(payload)


def write_message(payload: dict) -> None:
    """Write one LSP-framed message to stdout."""
    body = json.dumps(payload).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


def handle(msg: dict) -> dict | None:
    """Handle a JSON-RPC message. Returns response dict or None for notifications."""
    method = msg.get("method", "")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "echo-mcp-server", "version": "0.1.0"},
            },
        }

    if method == "initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "echo_tool",
                        "description": "Echoes back the arguments",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                        },
                    }
                ]
            },
        }

    if method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(args)}],
                "isError": False,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> None:
    sys.stderr.write(STDERR_MARKER + "\n")
    sys.stderr.flush()

    while True:
        msg = read_message()
        if msg is None:
            break
        response = handle(msg)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
