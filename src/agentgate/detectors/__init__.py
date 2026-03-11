"""Built-in detector pipeline — pattern-based attack detection for tool call arguments."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentgate.models import DetectorResult, ToolCall

# Detector registry — maps config names to their module paths.
# Each detector module must expose a `detect(tool_call: ToolCall) -> DetectorResult` function.
REGISTRY: dict[str, str] = {
    "sql_injection": "agentgate.detectors.sql_injection",
    "path_traversal": "agentgate.detectors.path_traversal",
    "command_injection": "agentgate.detectors.command_injection",
    "ssrf_private_ip": "agentgate.detectors.ssrf",
    "secrets_in_params": "agentgate.detectors.secrets",
}


def run_all(tool_call: ToolCall, enabled: dict[str, bool]) -> list[DetectorResult]:
    """Run all enabled detectors against a tool call and return results.

    Args:
        tool_call: The tool call to scan.
        enabled: Mapping of detector name to enabled flag (from DetectorsConfig).

    Returns:
        List of DetectorResult for detectors that matched.
    """
    # TODO: Import and invoke each enabled detector
    raise NotImplementedError("Detector pipeline not yet implemented")
