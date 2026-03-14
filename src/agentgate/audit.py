"""SQLite audit writer — append-only log with SHA-256 hash chaining for tamper evidence."""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger(__name__)

_SHUTDOWN = object()

_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    tool_name        TEXT    NOT NULL,
    arguments        TEXT    NOT NULL,
    decision         TEXT    NOT NULL,
    matched_rule     TEXT,
    matched_detector TEXT,
    message          TEXT,
    prev_hash        TEXT    NOT NULL,
    entry_hash       TEXT    NOT NULL
);
"""


@dataclass(frozen=True)
class _QueueEntry:
    timestamp: str
    session_id: str
    tool_name: str
    arguments_json: str
    decision: str
    matched_rule: str | None
    matched_detector: str | None
    message: str | None


def _compute_hash(
    prev_hash: str,
    timestamp: str,
    tool_name: str,
    arguments_json: str,
    decision: str,
) -> str:
    """Compute SHA-256 hash for an audit entry."""
    payload = f"{prev_hash}|{timestamp}|{tool_name}|{arguments_json}|{decision}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(db_path: str | Path) -> tuple[bool, int]:
    """Verify hash chain integrity of an audit database. Read-only.

    Returns (is_valid, row_count).
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT prev_hash, timestamp, tool_name, arguments, decision, entry_hash "
        "FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()

    expected_prev = "genesis"
    for prev_hash, ts, tool, args, decision, entry_hash in rows:
        if prev_hash != expected_prev:
            return (False, len(rows))
        recomputed = _compute_hash(prev_hash, ts, tool, args, decision)
        if recomputed != entry_hash:
            return (False, len(rows))
        expected_prev = entry_hash
    return (True, len(rows))


class AuditWriter:
    """Append-only SQLite audit writer with SHA-256 hash chaining.

    Thread-safe: the public log() method enqueues and returns immediately.
    SQLite connection lives exclusively in the background thread.
    """

    def __init__(self, db_path: str | Path = "agentgate_audit.db") -> None:
        """Create the audit_log table if needed, start the background thread."""
        self.db_path = Path(db_path)
        self._queue: queue.Queue[_QueueEntry | object] = queue.Queue()
        self._closed = False

        # Read last hash for resume support (short-lived connection on caller thread)
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        self._prev_hash = row[0] if row else "genesis"
        conn.close()

        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()

    def log(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Literal["allow", "block"],
        matched_rule: str | None = None,
        matched_detector: str | None = None,
        message: str | None = None,
    ) -> None:
        """Enqueue an audit entry. Non-blocking. Returns immediately.

        Arguments dict is serialized to JSON string internally.
        Timestamp is captured at call time (not dequeue time).
        """
        if self._closed:
            log.warning("AuditWriter.log() called after close(), entry dropped")
            return
        timestamp = datetime.now(timezone.utc).isoformat()
        arguments_json = json.dumps(arguments, separators=(",", ":"), sort_keys=True, default=str)
        entry = _QueueEntry(
            timestamp=timestamp,
            session_id=session_id,
            tool_name=tool_name,
            arguments_json=arguments_json,
            decision=decision,
            matched_rule=matched_rule,
            matched_detector=matched_detector,
            message=message,
        )
        self._queue.put_nowait(entry)

    def close(self, timeout: float = 2.0) -> None:
        """Flush remaining entries and stop the background thread.

        Blocks up to `timeout` seconds waiting for the queue to drain.
        Safe to call multiple times.
        """
        if self._closed:
            return
        self._closed = True
        self._queue.put(_SHUTDOWN)
        self._thread.join(timeout=timeout)

    def verify_chain(self) -> tuple[bool, int]:
        """Walk the full audit log and verify hash chain integrity.

        Returns (is_valid, row_count). Delegates to module-level verify_chain().
        """
        return verify_chain(self.db_path)

    def _writer_loop(self) -> None:
        """Background thread loop: drain queue, hash, write to SQLite."""
        conn = sqlite3.connect(str(self.db_path))
        prev_hash = self._prev_hash

        while True:
            entry = self._queue.get()
            if entry is _SHUTDOWN:
                self._queue.task_done()
                break

            entry_hash = _compute_hash(
                prev_hash,
                entry.timestamp,
                entry.tool_name,
                entry.arguments_json,
                entry.decision,
            )
            conn.execute(
                "INSERT INTO audit_log "
                "(timestamp, session_id, tool_name, arguments, decision, "
                "matched_rule, matched_detector, message, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.timestamp,
                    entry.session_id,
                    entry.tool_name,
                    entry.arguments_json,
                    entry.decision,
                    entry.matched_rule,
                    entry.matched_detector,
                    entry.message,
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()
            prev_hash = entry_hash
            self._queue.task_done()

        conn.close()
