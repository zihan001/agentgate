"""Command injection detector — flags shell metacharacters in string parameters."""

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


# Known shell commands that indicate injection intent after an operator
_KNOWN_COMMANDS = (
    r"rm|curl|wget|cat|echo|sh|bash|zsh|python[23]?|perl|ruby|nc|ncat"
    r"|chmod|chown|sudo|kill|pkill|dd|mkfifo|tee|xargs|find|grep|sed|awk"
    r"|eval|exec|source|export|env|nohup|setsid"
)

# Category 1: Shell operators followed by command-like tokens
_SEMICOLON_CMD = re.compile(
    rf";\s*(?:{_KNOWN_COMMANDS})\b|;\s*[./~]", re.IGNORECASE
)
_AND_CMD = re.compile(
    rf"&&\s*(?:{_KNOWN_COMMANDS})\b|&&\s*[./~]", re.IGNORECASE
)
_OR_CMD = re.compile(
    rf"\|\|\s*(?:{_KNOWN_COMMANDS})\b|\|\|\s*[./~]", re.IGNORECASE
)
_PIPE_CMD = re.compile(
    rf"(?<!\|)\|\s*(?:{_KNOWN_COMMANDS})\b", re.IGNORECASE
)
_REDIRECT = re.compile(r">{1,2}\s*[/~.]")

# Category 2: Command substitution — always suspicious
_BACKTICK = re.compile(r"`[^`]+`")
_DOLLAR_PAREN = re.compile(r"\$\([^)]+\)")

# Category 3: Embedded newlines
_NEWLINE = re.compile(r"\n")

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SEMICOLON_CMD, "shell command after semicolon"),
    (_AND_CMD, "shell command after &&"),
    (_OR_CMD, "shell command after ||"),
    (_PIPE_CMD, "pipe to shell command"),
    (_REDIRECT, "output redirection to file"),
    (_BACKTICK, "backtick command substitution"),
    (_DOLLAR_PAREN, "$() command substitution"),
    (_NEWLINE, "embedded newline"),
]


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for command injection patterns.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = _extract_strings(tool_call.arguments)

    for param_path, value in strings:
        for pattern, label in _PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="command_injection",
                    detail=f"Command injection detected in param '{param_path}': {label}",
                )

    return DetectorResult(matched=False, detector_name="command_injection")
