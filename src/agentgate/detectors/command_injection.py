"""Command injection detector — flags shell metacharacters in string parameters."""

from __future__ import annotations

import re

from agentgate.detectors._util import extract_strings
from agentgate.models import DetectorResult, ToolCall


# Known shell commands that indicate injection intent after an operator
_KNOWN_COMMANDS = (
    r"rm|curl|wget|cat|echo|sh|bash|zsh|python[23]?|perl|ruby|nc|ncat"
    r"|chmod|chown|sudo|kill|pkill|dd|mkfifo|tee|xargs|find|grep|sed|awk"
    r"|eval|exec|source|export|env|nohup|setsid"
)

# Category 1: Shell operators followed by command-like tokens
_SEMICOLON_CMD = re.compile(rf";\s*(?:{_KNOWN_COMMANDS})\b|;\s*[./~]", re.IGNORECASE)
_AND_CMD = re.compile(rf"&&\s*(?:{_KNOWN_COMMANDS})\b|&&\s*[./~]", re.IGNORECASE)
_OR_CMD = re.compile(rf"\|\|\s*(?:{_KNOWN_COMMANDS})\b|\|\|\s*[./~]", re.IGNORECASE)
_PIPE_CMD = re.compile(rf"(?<!\|)\|\s*(?:{_KNOWN_COMMANDS})\b", re.IGNORECASE)
_REDIRECT = re.compile(r">{1,2}\s*[/~.]")

# Category 2: Command substitution — always suspicious
_BACKTICK = re.compile(r"`[^`]+`")
_DOLLAR_PAREN = re.compile(r"\$\([^)]+\)")

# Category 3: Embedded newline followed by a suspicious command
_NEWLINE_CMD = re.compile(rf"\n\s*(?:{_KNOWN_COMMANDS})\b|\n\s*[./~]", re.IGNORECASE)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_SEMICOLON_CMD, "shell command after semicolon"),
    (_AND_CMD, "shell command after &&"),
    (_OR_CMD, "shell command after ||"),
    (_PIPE_CMD, "pipe to shell command"),
    (_REDIRECT, "output redirection to file"),
    (_BACKTICK, "backtick command substitution"),
    (_DOLLAR_PAREN, "$() command substitution"),
    (_NEWLINE_CMD, "shell command after newline"),
]


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for command injection patterns.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = extract_strings(tool_call.arguments)

    for param_path, value in strings:
        for pattern, label in _PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="command_injection",
                    detail=f"Command injection detected in param '{param_path}': {label}",
                )

    return DetectorResult(matched=False, detector_name="command_injection")
