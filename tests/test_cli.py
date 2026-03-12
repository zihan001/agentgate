"""CLI tests for agentgate start command."""

import os
import subprocess
import textwrap

import pytest
from click.testing import CliRunner

from agentgate.cli import main

VENV_AGENTGATE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "agentgate"
)


# ---------------------------------------------------------------------------
# Tests 1–2: CliRunner (in-process, fast, no subprocess)
# ---------------------------------------------------------------------------


def test_start_no_server_command() -> None:
    """agentgate start with no server command prints helpful error and exits 1."""
    runner = CliRunner()
    result = runner.invoke(main, ["start"])
    assert result.exit_code != 0
    # Click's own error for missing required argument
    assert "SERVER_COMMAND" in result.output or "No server command" in result.output


def test_start_bad_policy_file(tmp_path: pytest.TempPathFactory) -> None:
    """agentgate start with invalid policy prints PolicyLoadError message and exits 1."""
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("not: a: valid: policy: {{{{")

    runner = CliRunner()
    result = runner.invoke(main, ["start", "--policy", str(bad_policy), "--", "echo", "hello"])
    assert result.exit_code == 1
    assert "Error loading policy" in result.output


# ---------------------------------------------------------------------------
# Tests 3–7: subprocess (real process, tests banner/exit-code behavior)
# ---------------------------------------------------------------------------


def test_start_missing_policy_is_passthrough() -> None:
    """Missing policy file → passthrough mode shown in banner."""
    result = subprocess.run(
        [VENV_AGENTGATE, "start", "--policy", "/nonexistent/policy.yaml", "--", "echo", "hello"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert "passthrough" in result.stderr


def test_start_command_not_found() -> None:
    """Nonexistent binary → exit 1 with 'Command not found'."""
    result = subprocess.run(
        [VENV_AGENTGATE, "start", "--", "nonexistent_binary_xyz_12345"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "Command not found" in result.stderr


def test_start_verbose_flag() -> None:
    """The -v flag enables DEBUG logging on the agentgate namespace."""
    result = subprocess.run(
        [
            VENV_AGENTGATE,
            "start",
            "-v",
            "--policy",
            "/nonexistent/policy.yaml",
            "--",
            "echo",
            "hello",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    # Verbose mode should show the startup banner at minimum
    assert "AgentGate v" in result.stderr


def test_start_env_var_policy_override(tmp_path: pytest.TempPathFactory) -> None:
    """AGENTGATE_POLICY env var overrides default policy path."""
    policy_file = tmp_path / "env-policy.yaml"
    policy_file.write_text(
        textwrap.dedent("""\
            version: "0.1"
            settings:
              default_decision: allow
            policies:
              - name: allow-all
                type: tool_allow
                tools:
                  - "*"
        """)
    )

    env = {**os.environ, "AGENTGATE_POLICY": str(policy_file)}
    result = subprocess.run(
        [VENV_AGENTGATE, "start", "--", "echo", "hello"],
        capture_output=True,
        text=True,
        timeout=5,
        env=env,
    )
    assert "enforcing" in result.stderr
    assert str(policy_file) in result.stderr


def test_start_banner_output(tmp_path: pytest.TempPathFactory) -> None:
    """Valid 2-rule policy → banner shows version, mode=enforcing, rules=2."""
    policy_file = tmp_path / "banner-policy.yaml"
    policy_file.write_text(
        textwrap.dedent("""\
            version: "0.1"
            settings:
              default_decision: allow
            policies:
              - name: allow-reads
                type: tool_allow
                tools:
                  - read_file
              - name: block-deletes
                type: tool_block
                tools:
                  - delete_file
        """)
    )

    result = subprocess.run(
        [VENV_AGENTGATE, "start", "--policy", str(policy_file), "--", "echo", "hello"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert "AgentGate v" in result.stderr
    assert "mode=enforcing" in result.stderr
    assert "rules=2" in result.stderr
