"""Pytest fixtures for AgentGate tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentgate.models import PolicyConfig, ToolCall
from agentgate.policy import CompiledPolicy, load_and_compile

# Path to the echo MCP server used by proxy tests
ECHO_SERVER_PATH = str(Path(__file__).parent / "helpers" / "echo_mcp_server.py")

# Path to the policy-aware proxy test harness
PROXY_WITH_POLICY_PATH = str(Path(__file__).parent / "helpers" / "proxy_with_policy.py")


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


@pytest.fixture()
def proxy_with_policy(tmp_path, echo_server_cmd):
    """Factory: spawn a proxy with a given policy YAML string. Returns subprocess.Popen."""
    procs = []

    def _spawn(yaml_content: str) -> subprocess.Popen:
        policy_path = tmp_path / "agentgate.yaml"
        policy_path.write_text(yaml_content, encoding="utf-8")

        env = os.environ.copy()
        env["AGENTGATE_TEST_POLICY"] = str(policy_path)

        cmd = [sys.executable, PROXY_WITH_POLICY_PATH] + echo_server_cmd
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(Path(__file__).parent.parent),
        )
        procs.append(proc)
        return proc

    yield _spawn

    for proc in procs:
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


# ---------------------------------------------------------------------------
# Shared fixtures for PR2+ reuse
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_tool_call():
    """Factory: build a ToolCall with defaults."""

    def _make(
        tool_name: str = "echo_tool",
        arguments: dict | None = None,
        call_id: int | str | None = 1,
    ) -> ToolCall:
        return ToolCall(
            tool_name=tool_name,
            arguments=arguments or {},
            call_id=call_id,
        )

    return _make


@pytest.fixture()
def compiled_policy_from_yaml(tmp_path):
    """Factory: compile a YAML policy string into a CompiledPolicy."""

    def _compile(yaml_content: str) -> CompiledPolicy:
        policy_path = tmp_path / "test_policy.yaml"
        policy_path.write_text(yaml_content, encoding="utf-8")
        return load_and_compile(str(policy_path))

    return _compile


@pytest.fixture()
def sample_policy() -> CompiledPolicy:
    """Load agentgate.yaml.example as a CompiledPolicy. Proves the golden path config is valid."""
    example_path = Path(__file__).parent.parent / "agentgate.yaml.example"
    return load_and_compile(str(example_path))


@pytest.fixture()
def minimal_policy() -> CompiledPolicy:
    """A minimal allow-all policy with no rules. Default decision: allow."""
    config = PolicyConfig(version="0.1")
    return CompiledPolicy(config=config, regexes={})
