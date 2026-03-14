#!/usr/bin/env python3
"""Minimal email MCP server for AgentGate demos.

Speaks LSP-framed JSON-RPC over stdin/stdout (same protocol as
tests/helpers/echo_mcp_server.py). Exposes a single ``send_email`` tool
that logs to stderr and returns a success message — no actual email is sent.

No external dependencies: uses only ``json`` and ``sys`` from stdlib.
"""

from __future__ import annotations

import json
import sys


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
    req_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "email-server", "version": "0.1.0"},
            },
        }

    if method == "initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "send_email",
                        "description": "Send an email (simulated).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string", "description": "Recipient email"},
                                "subject": {"type": "string", "description": "Subject line"},
                                "body": {"type": "string", "description": "Email body"},
                            },
                            "required": ["to", "subject", "body"],
                        },
                    }
                ]
            },
        }

    if method == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        to = args.get("to", "unknown")
        print(f"[EMAIL] to={to} subject={args.get('subject', '')}", file=sys.stderr)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": f"Email sent to {to}"}],
            },
        }

    # Notifications (no id) get no response
    if req_id is None:
        return None

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> None:
    while True:
        msg = read_message()
        if msg is None:
            break
        response = handle(msg)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
