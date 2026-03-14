"""In-memory session store — sliding window deque of recent tool calls and responses for chain detection."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class SessionEntry:
    """A single recorded tool call and its response."""

    tool_name: str
    arguments: dict[str, Any]
    response_text: str | None = None
    timestamp: float = 0.0


class SessionStore:
    """Sliding window of recent tool calls for chain detection."""

    def __init__(self, max_size: int = 50) -> None:
        self._entries: deque[SessionEntry] = deque(maxlen=max_size)

    def record_request(self, tool_name: str, arguments: dict[str, Any]) -> SessionEntry:
        """Record an allowed tool call. Returns the entry (response_text=None)."""
        entry = SessionEntry(
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.monotonic(),
        )
        self._entries.append(entry)
        return entry

    def record_response(self, entry: SessionEntry, response_text: str) -> None:
        """Attach response text to a previously recorded entry."""
        entry.response_text = response_text

    def recent(self, n: int | None = None) -> list[SessionEntry]:
        """Return the last N entries (or all if n is None). Most recent last."""
        if n is None:
            return list(self._entries)
        return list(self._entries)[-n:]

    def clear(self) -> None:
        """Clear all entries."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
