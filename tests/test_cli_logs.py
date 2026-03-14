"""Tests for the agentgate logs CLI command."""

from __future__ import annotations

import json
import sqlite3

import pytest
from click.testing import CliRunner

from agentgate.audit import AuditWriter
from agentgate.cli import main


@pytest.fixture()
def seed_db(tmp_path):
    """Create a seeded audit DB with 5 entries: 3 allow, 2 block, across 2 sessions."""
    db = tmp_path / "test_audit.db"
    w = AuditWriter(db)
    # Entry 1: allow, session-a (has matched_rule but no detector/message)
    w.log(
        session_id="session-a",
        tool_name="read_file",
        arguments={"path": "/data/file1.txt"},
        decision="allow",
        matched_rule="allow-reads",
    )
    # Entry 2: block, session-a (all fields populated)
    w.log(
        session_id="session-a",
        tool_name="delete_file",
        arguments={"path": "/etc/passwd"},
        decision="block",
        matched_rule="block-deletes",
        matched_detector="path_traversal",
        message="Blocked by path_traversal detector",
    )
    # Entry 3: allow, session-b (no matched_rule, no detector, no message)
    w.log(
        session_id="session-b",
        tool_name="read_file",
        arguments={"path": "/data/file2.txt"},
        decision="allow",
    )
    # Entry 4: allow, session-a
    w.log(
        session_id="session-a",
        tool_name="list_dir",
        arguments={"path": "/data"},
        decision="allow",
    )
    # Entry 5: block, session-b
    w.log(
        session_id="session-b",
        tool_name="write_file",
        arguments={"path": "/etc/shadow", "content": "x"},
        decision="block",
        matched_rule="block-system",
        message="System file blocked",
    )
    w.close()
    return db


def _parse_lines(output: str) -> list[dict]:
    """Parse JSON Lines output into list of dicts."""
    if not output.strip():
        return []
    return [json.loads(line) for line in output.strip().split("\n")]


def test_logs_no_db(tmp_path):
    """Missing DB file -> stderr error, exit 1."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(tmp_path / "nope.db")])
    assert result.exit_code == 1
    assert "Audit database not found" in result.output


def test_logs_empty_db(tmp_path):
    """DB exists, table exists, 0 rows -> empty stdout, exit 0."""
    db = tmp_path / "empty.db"
    w = AuditWriter(db)
    w.close()

    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(db)])
    assert result.exit_code == 0
    assert result.output == ""


def test_logs_all_entries(seed_db):
    """No filters -> all rows in JSON lines, chronological order."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db)])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 5
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids)


def test_logs_tail(seed_db):
    """--tail 2 on 5 entries -> last 2 entries, chronological."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--tail", "2"])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 2
    # Last 2 entries are ids 4 and 5
    assert rows[0]["id"] == 4
    assert rows[1]["id"] == 5


def test_logs_session_filter(seed_db):
    """--session session-a -> only rows with that session_id."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--session", "session-a"])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 3
    assert all(r["session_id"] == "session-a" for r in rows)


def test_logs_decision_filter(seed_db):
    """--decision block -> only block rows."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--decision", "block"])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 2
    assert all(r["decision"] == "block" for r in rows)


def test_logs_combined_filters(seed_db):
    """--tail 1 --decision block --session session-a -> correct intersection."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "logs",
            "--db",
            str(seed_db),
            "--tail",
            "1",
            "--decision",
            "block",
            "--session",
            "session-a",
        ],
    )
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 1
    assert rows[0]["session_id"] == "session-a"
    assert rows[0]["decision"] == "block"
    assert rows[0]["tool_name"] == "delete_file"


def test_logs_no_matches(seed_db):
    """Filters that match nothing -> empty stdout, exit 0."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--session", "nonexistent"])
    assert result.exit_code == 0
    assert result.output == ""


def test_logs_arguments_parsed(seed_db):
    """arguments field is a dict in output, not a double-encoded string."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--tail", "1"])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 1
    assert isinstance(rows[0]["arguments"], dict)


def test_logs_null_fields(seed_db):
    """Allowed entry with no matched_rule -> null in JSON output."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["logs", "--db", str(seed_db), "--session", "session-b", "--decision", "allow"]
    )
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 1
    # Entry 3: allow, session-b, no rule/detector/message
    assert rows[0]["matched_rule"] is None
    assert rows[0]["matched_detector"] is None
    assert rows[0]["message"] is None


def test_logs_verify_intact(seed_db):
    """--verify on valid DB -> 'OK' on stderr, exit 0."""
    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--verify"])
    assert result.exit_code == 0
    assert "OK: 5 entries, chain intact" in result.output


def test_logs_verify_broken(seed_db):
    """--verify on tampered DB -> 'FAIL' on stderr, exit 1."""
    # Tamper with one entry's hash
    conn = sqlite3.connect(str(seed_db))
    conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 3")
    conn.commit()
    conn.close()

    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(seed_db), "--verify"])
    assert result.exit_code == 1
    assert "FAIL: chain broken" in result.output


def test_logs_db_option(tmp_path):
    """--db /path/to/other.db -> reads from specified path."""
    custom_path = tmp_path / "subdir" / "custom.db"
    custom_path.parent.mkdir()
    w = AuditWriter(custom_path)
    w.log(
        session_id="s1",
        tool_name="test_tool",
        arguments={"key": "val"},
        decision="allow",
    )
    w.close()

    runner = CliRunner()
    result = runner.invoke(main, ["logs", "--db", str(custom_path)])
    assert result.exit_code == 0

    rows = _parse_lines(result.output)
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "test_tool"
