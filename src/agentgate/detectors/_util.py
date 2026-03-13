"""Shared utilities for detector modules."""

from __future__ import annotations

from typing import Any


def extract_strings(arguments: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract all (key_path, string_value) pairs from arguments.

    Walks dicts, lists, and nested lists to find every string leaf value.
    Returns a list of (dotted_key_path, string_value) tuples.
    """
    results: list[tuple[str, str]] = []
    for key, value in arguments.items():
        path = f"{prefix}.{key}" if prefix else key
        _collect(value, path, results)
    return results


def _collect(value: Any, path: str, results: list[tuple[str, str]]) -> None:
    """Recursively collect string values from an arbitrary JSON-like structure."""
    if isinstance(value, str):
        results.append((path, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            _collect(v, f"{path}.{k}", results)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _collect(item, f"{path}[{i}]", results)
