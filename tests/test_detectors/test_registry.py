"""Unit tests for the detector registry run_all() pipeline."""

from __future__ import annotations

from agentgate.detectors import run_all
from agentgate.models import ToolCall

ALL_ENABLED = {
    "sql_injection": True,
    "path_traversal": True,
    "command_injection": True,
    "ssrf_private_ip": True,
    "secrets_in_params": True,
}


def _call(arguments: dict) -> ToolCall:
    return ToolCall(tool_name="test_tool", arguments=arguments)


# --- Test 1: Clean call, no detectors fire ---


def test_run_all_clean_call_returns_empty():
    results = run_all(_call({"text": "hello world"}), ALL_ENABLED)
    assert results == []


# --- Test 2: Path traversal fires ---


def test_run_all_path_traversal():
    results = run_all(_call({"path": "../../etc/passwd"}), ALL_ENABLED)
    assert len(results) >= 1
    names = [r.detector_name for r in results]
    assert "path_traversal" in names


# --- Test 3: Multiple detectors fire (path traversal + secrets) ---


def test_run_all_multiple_detectors():
    results = run_all(
        _call({"path": "../../etc/passwd", "key": "AKIA1234567890ABCDEF"}),
        ALL_ENABLED,
    )
    names = [r.detector_name for r in results]
    assert "path_traversal" in names
    assert "secrets_in_params" in names
    assert len(names) >= 2


# --- Test 4: Disabled detector is skipped ---


def test_run_all_disabled_detector_skipped():
    enabled = {**ALL_ENABLED, "path_traversal": False}
    results = run_all(_call({"path": "../../etc/passwd"}), enabled)
    names = [r.detector_name for r in results]
    assert "path_traversal" not in names


# --- Test 5: SQL injection fires ---


def test_run_all_sql_injection():
    results = run_all(_call({"query": "DROP TABLE users"}), ALL_ENABLED)
    names = [r.detector_name for r in results]
    assert "sql_injection" in names


# --- Test 6: SSRF fires ---


def test_run_all_ssrf():
    results = run_all(_call({"url": "http://169.254.169.254/"}), ALL_ENABLED)
    names = [r.detector_name for r in results]
    assert "ssrf_private_ip" in names


# --- Test 7: Command injection fires ---


def test_run_all_command_injection():
    results = run_all(_call({"cmd": "file.txt; rm -rf /"}), ALL_ENABLED)
    names = [r.detector_name for r in results]
    assert "command_injection" in names


# --- Test 8: Empty enabled dict, all skipped ---


def test_run_all_empty_enabled_skips_all():
    results = run_all(_call({"path": "../../etc/passwd"}), {})
    assert results == []
