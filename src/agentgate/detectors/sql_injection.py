"""SQL injection detector — flags destructive SQL patterns in string parameters."""

from __future__ import annotations

import re

from agentgate.detectors._util import extract_strings
from agentgate.models import DetectorResult, ToolCall


_SQL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Tier 1: Destructive statements
    (re.compile(r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b", re.I), "DROP statement"),
    (re.compile(r"\bDELETE\s+FROM\b", re.I), "DELETE FROM statement"),
    (re.compile(r"\bTRUNCATE\s+(TABLE\s+)?\w", re.I), "TRUNCATE statement"),
    (re.compile(r"\bALTER\s+TABLE\b", re.I), "ALTER TABLE statement"),
    (re.compile(r"\bUPDATE\s+\S+\s+SET\b", re.I), "UPDATE...SET statement"),
    (re.compile(r"\bINSERT\s+INTO\b", re.I), "INSERT INTO statement"),
    (re.compile(r"\bEXEC(UTE)?\s*\(", re.I), "EXEC/EXECUTE call"),
    # Tier 2: Injection indicators
    (re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.I), "UNION SELECT"),
    (re.compile(r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.I), "OR tautology"),
    (re.compile(r";\s*--", re.I), "stacked query with comment"),
    (
        re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|TRUNCATE|ALTER|EXEC)\b", re.I),
        "stacked destructive query",
    ),
]


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for SQL injection patterns.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = extract_strings(tool_call.arguments)

    for param_path, value in strings:
        for pattern, label in _SQL_PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="sql_injection",
                    detail=f"SQL injection detected in param '{param_path}': {label}",
                )

    return DetectorResult(matched=False, detector_name="sql_injection")
