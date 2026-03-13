"""Tests for SQL injection detector."""

from agentgate.detectors.sql_injection import detect
from agentgate.models import ToolCall


def _call(arguments: dict) -> ToolCall:
    """Build a ToolCall with the given arguments."""
    return ToolCall(tool_name="query_db", arguments=arguments, call_id=1)


# ── Positive cases (7) — must detect ────────────────────────────────────


def test_drop_table():
    result = detect(_call({"query": "DROP TABLE users"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "DROP statement" in result.detail


def test_delete_from():
    result = detect(_call({"query": "'; DELETE FROM accounts; --"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "DELETE FROM" in result.detail or "stacked" in result.detail


def test_union_select():
    result = detect(_call({"query": "' UNION SELECT password FROM users --"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "UNION SELECT" in result.detail


def test_or_tautology():
    result = detect(_call({"query": "' OR 1=1 --"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "OR tautology" in result.detail


def test_update_set():
    result = detect(_call({"query": "UPDATE users SET role='admin' WHERE id=1"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "UPDATE...SET" in result.detail


def test_truncate_table():
    result = detect(_call({"query": "TRUNCATE TABLE sessions"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "TRUNCATE" in result.detail


def test_nested_param_injection():
    result = detect(_call({"config": {"sql": "DROP TABLE logs"}}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "config.sql" in result.detail
    assert "DROP statement" in result.detail


# ── Negative cases (7) — must NOT detect ────────────────────────────────


def test_benign_select():
    result = detect(_call({"query": "SELECT * FROM sales WHERE quarter = 'Q4'"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_english_prose_select():
    result = detect(_call({"text": "The SELECT committee met on Tuesday"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_english_prose_drop():
    result = detect(_call({"text": "Please drop the meeting notes in the shared folder"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_normal_string_params():
    result = detect(_call({"name": "John", "email": "john@example.com"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_empty_arguments():
    result = detect(_call({}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_numeric_params_ignored():
    result = detect(_call({"count": 42, "active": True, "path": "/data/file.txt"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


def test_benign_insert_english():
    result = detect(_call({"text": "Insert the new section after paragraph 3"}))
    assert result.matched is False
    assert result.detector_name == "sql_injection"


# ── Edge cases (2) ──────────────────────────────────────────────────────


def test_case_insensitive():
    result = detect(_call({"query": "dRoP tAbLe users"}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"


def test_list_param_scanning():
    result = detect(_call({"queries": ["SELECT 1", "DROP TABLE x"]}))
    assert result.matched is True
    assert result.detector_name == "sql_injection"
    assert "queries[1]" in result.detail
