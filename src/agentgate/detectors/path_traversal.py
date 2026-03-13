"""Path traversal detector — flags ../ sequences, sensitive absolute paths, and null byte injection."""

from __future__ import annotations

import re
from typing import Any

from agentgate.models import DetectorResult, ToolCall


def _extract_strings(arguments: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract all (key_path, string_value) pairs from arguments."""
    results: list[tuple[str, str]] = []
    for key, value in arguments.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, str):
            results.append((path, value))
        elif isinstance(value, dict):
            results.extend(_extract_strings(value, path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_path = f"{path}[{i}]"
                if isinstance(item, str):
                    results.append((item_path, item))
                elif isinstance(item, dict):
                    results.extend(_extract_strings(item, item_path))
    return results


# --- Pattern categories ---

# Category 1: Traversal sequences (../ ..\ and URL-encoded variants)
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c|\\)", re.IGNORECASE)

# Category 2: Sensitive path prefixes (checked via str.startswith)
_SENSITIVE_PREFIXES: list[str] = [
    "/etc/",
    "/root/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/var/log/",
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.bashrc",
    "~/.bash_history",
    "~/.profile",
    "~/.zshrc",
    "~/.bash_profile",
]

# Category 2b: /home/<user>/.<sensitive_dir> pattern
_HOME_SENSITIVE_RE = re.compile(r"^/home/[^/]+/\.(?:ssh|aws|gnupg)")

# Category 3: Null byte injection (encoded representations)
_NULL_BYTE_RE = re.compile(r"%00|\\x00|\\0")


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for path traversal indicators.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = _extract_strings(tool_call.arguments)

    for param_path, value in strings:
        # Category 1: Traversal sequences (../  ..\ and encoded variants)
        if _TRAVERSAL_RE.search(value):
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Path traversal sequence in param '{param_path}'",
            )

        # Category 2: Sensitive absolute path prefixes
        for prefix in _SENSITIVE_PREFIXES:
            if value.startswith(prefix):
                return DetectorResult(
                    matched=True,
                    detector_name="path_traversal",
                    detail=f"Sensitive path prefix '{prefix}' in param '{param_path}'",
                )

        # Category 2b: /home/<user>/.ssh etc
        if _HOME_SENSITIVE_RE.search(value):
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Sensitive home directory path in param '{param_path}'",
            )

        # Category 3: Null byte injection
        if _NULL_BYTE_RE.search(value) or "\x00" in value:
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Null byte injection in param '{param_path}'",
            )

    return DetectorResult(matched=False, detector_name="path_traversal")
