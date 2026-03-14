"""Tests for the SQLite audit writer with SHA-256 hash chaining."""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone

import pytest

from agentgate.audit import AuditWriter, _compute_hash


@pytest.fixture()
def writer(tmp_path):
    db = tmp_path / "test_audit.db"
    w = AuditWriter(db)
    yield w
    w.close()


def _count_rows(db_path) -> int:
    conn = sqlite3.connect(str(db_path))
    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    return count


def _read_rows(db_path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    conn.close()
    return rows


def _log_sample(w: AuditWriter, **overrides) -> None:
    defaults = {
        "session_id": "test-session",
        "tool_name": "read_file",
        "arguments": {"path": "/tmp/test.txt"},
        "decision": "allow",
    }
    defaults.update(overrides)
    w.log(**defaults)


# --- Test 1: Table creation ---


def test_creates_table(tmp_path):
    db = tmp_path / "audit.db"
    w = AuditWriter(db)
    w.close()

    conn = sqlite3.connect(str(db))
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
    ).fetchall()
    conn.close()
    assert len(tables) == 1


# --- Test 2: Log and read back ---


def test_log_and_read_back(writer):
    writer.log(
        session_id="s1",
        tool_name="read_file",
        arguments={"path": "/etc/passwd"},
        decision="allow",
        matched_rule="allow-reads",
        matched_detector=None,
        message=None,
    )
    writer.close()

    rows = _read_rows(writer.db_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["session_id"] == "s1"
    assert row["tool_name"] == "read_file"
    assert row["decision"] == "allow"
    assert row["matched_rule"] == "allow-reads"
    assert row["prev_hash"] is not None
    assert row["entry_hash"] is not None


# --- Test 3: Genesis hash ---


def test_genesis_hash(writer):
    _log_sample(writer)
    writer.close()

    rows = _read_rows(writer.db_path)
    assert rows[0]["prev_hash"] == "genesis"


# --- Test 4: Hash chain two entries ---


def test_hash_chain_two_entries(writer):
    _log_sample(writer, tool_name="read_file")
    _log_sample(writer, tool_name="write_file")
    writer.close()

    rows = _read_rows(writer.db_path)
    assert len(rows) == 2
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]


# --- Test 5: Hash determinism ---


def test_hash_determinism():
    h1 = _compute_hash("genesis", "2024-01-01T00:00:00", "tool", '{"a":1}', "allow")
    h2 = _compute_hash("genesis", "2024-01-01T00:00:00", "tool", '{"a":1}', "allow")
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest


# --- Test 6: Verify chain valid ---


def test_verify_chain_valid(writer):
    for i in range(5):
        _log_sample(writer, tool_name=f"tool_{i}")
    writer.close()

    valid, count = writer.verify_chain()
    assert valid is True
    assert count == 5


# --- Test 7: Verify chain tampered ---


def test_verify_chain_tampered(writer):
    for i in range(3):
        _log_sample(writer, tool_name=f"tool_{i}")
    writer.close()

    # Tamper with one row
    conn = sqlite3.connect(str(writer.db_path))
    conn.execute("UPDATE audit_log SET arguments = '{\"hacked\":true}' WHERE id = 2")
    conn.commit()
    conn.close()

    valid, count = writer.verify_chain()
    assert valid is False
    assert count == 3


# --- Test 8: Verify chain empty ---


def test_verify_chain_empty(tmp_path):
    db = tmp_path / "empty.db"
    w = AuditWriter(db)
    w.close()

    valid, count = w.verify_chain()
    assert valid is True
    assert count == 0


# --- Test 9: Close flushes ---


def test_close_flushes(tmp_path):
    db = tmp_path / "flush.db"
    w = AuditWriter(db)
    for i in range(10):
        _log_sample(w, tool_name=f"tool_{i}")
    w.close()

    assert _count_rows(db) == 10


# --- Test 10: Close idempotent ---


def test_close_idempotent(writer):
    _log_sample(writer)
    writer.close()
    writer.close()  # Should not raise


# --- Test 11: Resume existing DB ---


def test_resume_existing_db(tmp_path):
    db = tmp_path / "resume.db"

    w1 = AuditWriter(db)
    for i in range(3):
        _log_sample(w1, tool_name=f"tool_{i}")
    w1.close()

    w2 = AuditWriter(db)
    _log_sample(w2, tool_name="tool_3")
    w2.close()

    valid, count = w2.verify_chain()
    assert valid is True
    assert count == 4


# --- Test 12: Timestamp is enqueue time ---


def test_timestamp_is_enqueue_time(writer):
    before = datetime.now(timezone.utc)
    _log_sample(writer)
    after = datetime.now(timezone.utc)
    writer.close()

    rows = _read_rows(writer.db_path)
    ts = datetime.fromisoformat(rows[0]["timestamp"])
    assert before <= ts <= after


# --- Test 13: Arguments sorted keys ---


def test_arguments_sorted_keys(writer):
    writer.log(
        session_id="s1",
        tool_name="tool",
        arguments={"b": 2, "a": 1},
        decision="allow",
    )
    writer.close()

    rows = _read_rows(writer.db_path)
    assert rows[0]["arguments"] == '{"a":1,"b":2}'


# --- Test 14: Concurrent writes ---


def test_concurrent_writes(tmp_path):
    db = tmp_path / "concurrent.db"
    w = AuditWriter(db)

    def log_entries(thread_id: int):
        for i in range(10):
            w.log(
                session_id=f"session-{thread_id}",
                tool_name=f"tool_{thread_id}_{i}",
                arguments={"thread": thread_id, "index": i},
                decision="allow",
            )

    threads = [threading.Thread(target=log_entries, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()

    assert _count_rows(db) == 50
    valid, count = w.verify_chain()
    assert valid is True
    assert count == 50


# --- Test 15: Log latency under 2ms ---


def test_log_latency_under_2ms(tmp_path):
    db = tmp_path / "latency.db"
    w = AuditWriter(db)

    latencies = []
    for i in range(100):
        start = time.perf_counter()
        w.log(
            session_id="perf-test",
            tool_name=f"tool_{i}",
            arguments={"index": i},
            decision="allow",
        )
        latencies.append(time.perf_counter() - start)
    w.close()

    latencies.sort()
    p99 = latencies[98]  # 99th percentile of 100 samples
    assert p99 < 0.002, f"p99 latency {p99*1000:.2f}ms exceeds 2ms"
