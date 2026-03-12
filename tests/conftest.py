"""Pytest fixtures for AgentGate tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Path to the echo MCP server used by proxy tests
ECHO_SERVER_PATH = str(Path(__file__).parent / "helpers" / "echo_mcp_server.py")


@pytest.fixture()
def echo_server_cmd() -> list[str]:
    """Command to run the echo MCP server."""
    return [sys.executable, ECHO_SERVER_PATH]


@pytest.fixture()
def proxy_process(echo_server_cmd: list[str]) -> subprocess.Popen:
    """Spawn the proxy wrapping the echo MCP server. Tears down on exit."""
    cmd = [sys.executable, "-m", "agentgate.proxy"] + echo_server_cmd
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(Path(__file__).parent.parent),
    )
    yield proc

    # Teardown
    if proc.poll() is None:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
