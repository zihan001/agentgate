"""Built-in detector pipeline — pattern-based attack detection for tool call arguments."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentgate.models import DetectorResult, ToolCall

from agentgate.detectors import (
    command_injection,
    path_traversal,
    secrets,
    sql_injection,
    ssrf,
)

log = logging.getLogger("agentgate.detectors")

# Maps DetectorsConfig field name -> detector module.
# Each module exposes detect(tool_call: ToolCall) -> DetectorResult.
_DETECTORS: dict[str, object] = {
    "sql_injection": sql_injection,
    "path_traversal": path_traversal,
    "command_injection": command_injection,
    "ssrf_private_ip": ssrf,
    "secrets_in_params": secrets,
}


def run_all(tool_call: ToolCall, enabled: dict[str, bool]) -> list[DetectorResult]:
    """Run all enabled detectors against a tool call and return matched results.

    Args:
        tool_call: The tool call to scan.
        enabled: Mapping of detector name to enabled flag (from DetectorsConfig).

    Returns:
        List of DetectorResult for detectors that matched (matched=True only).
    """
    results: list[DetectorResult] = []
    for name, module in _DETECTORS.items():
        if not enabled.get(name, False):
            continue
        try:
            result = module.detect(tool_call)  # type: ignore[attr-defined]
            if result.matched:
                results.append(result)
        except Exception:
            log.warning("Detector '%s' raised an exception, skipping", name, exc_info=True)
    return results
