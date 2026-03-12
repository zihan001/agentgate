"""Unit tests for JSON-RPC message parser — all synchronous, no I/O."""

from __future__ import annotations

import json

from agentgate.parser import build_error_response, parse_message


def _encode(obj: dict) -> bytes:
    return json.dumps(obj).encode()


# --- tools/call parsing ---


def test_parse_tools_call():
    payload = _encode(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
        }
    )
    parsed = parse_message(payload)
    assert parsed.kind == "tool_call"
    assert parsed.tool_call is not None
    assert parsed.tool_call.tool_name == "read_file"
    assert parsed.tool_call.arguments == {"path": "/etc/passwd"}
    assert parsed.tool_call.call_id == 3
    assert parsed.method == "tools/call"
    assert parsed.request_id == 3
    assert parsed.raw == payload


def test_parse_tools_call_empty_arguments():
    payload = _encode(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "list_files"},
        }
    )
    parsed = parse_message(payload)
    assert parsed.kind == "tool_call"
    assert parsed.tool_call is not None
    assert parsed.tool_call.arguments == {}


# --- Other requests ---


def test_parse_initialize_request():
    payload = _encode({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    parsed = parse_message(payload)
    assert parsed.kind == "request"
    assert parsed.method == "initialize"
    assert parsed.request_id == 1
    assert parsed.tool_call is None


def test_parse_tools_list_request():
    payload = _encode({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    parsed = parse_message(payload)
    assert parsed.kind == "request"
    assert parsed.method == "tools/list"
    assert parsed.request_id == 2


# --- Notifications ---


def test_parse_initialized_notification():
    payload = _encode({"jsonrpc": "2.0", "method": "initialized"})
    parsed = parse_message(payload)
    assert parsed.kind == "notification"
    assert parsed.method == "initialized"
    assert parsed.request_id is None


# --- Responses ---


def test_parse_response_with_result():
    payload = _encode(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2024-11-05"},
        }
    )
    parsed = parse_message(payload)
    assert parsed.kind == "response"
    assert parsed.request_id == 1
    assert parsed.method is None


def test_parse_error_response():
    payload = _encode(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"},
        }
    )
    parsed = parse_message(payload)
    assert parsed.kind == "response"
    assert parsed.request_id == 1


# --- Invalid messages ---


def test_parse_invalid_json():
    payload = b"not json at all"
    parsed = parse_message(payload)
    assert parsed.kind == "invalid"
    assert parsed.raw == b"not json at all"


def test_parse_json_not_object():
    payload = b"[1, 2, 3]"
    parsed = parse_message(payload)
    assert parsed.kind == "invalid"


def test_parse_tools_call_missing_name():
    payload = _encode(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"arguments": {"x": 1}},
        }
    )
    parsed = parse_message(payload)
    assert parsed.kind == "invalid"


# --- build_error_response ---


def test_build_error_response():
    result = build_error_response(3, -32600, "Blocked by policy")
    assert isinstance(result, bytes)
    decoded = json.loads(result)
    assert decoded["jsonrpc"] == "2.0"
    assert decoded["id"] == 3
    assert decoded["error"]["code"] == -32600
    assert decoded["error"]["message"] == "Blocked by policy"


# --- Raw bytes preservation ---


def test_raw_bytes_preserved_for_all_kinds():
    payloads = {
        "tool_call": _encode(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "t", "arguments": {}},
            }
        ),
        "request": _encode({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        "notification": _encode({"jsonrpc": "2.0", "method": "initialized"}),
        "response": _encode({"jsonrpc": "2.0", "id": 1, "result": {}}),
        "invalid": b"garbage",
    }
    for expected_kind, payload in payloads.items():
        parsed = parse_message(payload)
        assert parsed.kind == expected_kind, f"Expected {expected_kind}, got {parsed.kind}"
        assert parsed.raw is payload, f"raw bytes not preserved for kind={expected_kind}"
