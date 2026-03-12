"""Shared MCP client helpers for integration tests."""

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
