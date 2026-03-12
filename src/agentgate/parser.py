"""JSON-RPC message parsing — decodes MCP messages, extracts tool call method, name, and arguments."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from agentgate.models import ToolCall


class ParsedMessage(BaseModel):
    """Result of parsing a raw JSON-RPC payload."""

    kind: Literal["tool_call", "request", "notification", "response", "invalid"]
    raw: bytes
    tool_call: ToolCall | None = None
    request_id: str | int | None = None
    method: str | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


def parse_message(payload: bytes) -> ParsedMessage:
    """Classify a raw JSON-RPC payload and extract tool call info if applicable.

    Pure synchronous function — no I/O, no side effects.
    """
    try:
        msg = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ParsedMessage(kind="invalid", raw=payload)

    if not isinstance(msg, dict):
        return ParsedMessage(kind="invalid", raw=payload)

    request_id = msg.get("id")
    method = msg.get("method")

    if method is None:
        if "result" in msg or "error" in msg:
            return ParsedMessage(kind="response", raw=payload, request_id=request_id)
        return ParsedMessage(kind="invalid", raw=payload)

    if request_id is None:
        return ParsedMessage(kind="notification", raw=payload, method=method)

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name")
        if tool_name is None:
            return ParsedMessage(kind="invalid", raw=payload, request_id=request_id, method=method)
        arguments = params.get("arguments", {})
        tool_call = ToolCall(tool_name=tool_name, arguments=arguments, call_id=request_id)
        return ParsedMessage(
            kind="tool_call", raw=payload, tool_call=tool_call, request_id=request_id, method=method
        )

    return ParsedMessage(kind="request", raw=payload, request_id=request_id, method=method)


def build_error_response(request_id: str | int, code: int, message: str) -> bytes:
    """Build a JSON-RPC error response payload as bytes (not LSP-framed).

    The caller wraps this with write_message() which adds Content-Length framing.
    """
    return json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }).encode()
