"""Tests for the `agentgate eval` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agentgate.cli import main

REFERENCE_POLICY = Path(__file__).parent.parent / "eval" / "policies" / "eval_reference.yaml"


def test_eval_default_runs_and_passes() -> None:
    """agentgate eval with reference policy → exit 0, table in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(REFERENCE_POLICY)])
    assert result.exit_code == 0, f"stdout: {result.output}"
    assert "PASS" in result.output
    assert "Benign Utility" in result.output


def test_eval_custom_policy(tmp_path: Path) -> None:
    """--policy flag loads a different policy file."""
    policy = tmp_path / "custom.yaml"
    policy.write_text(
        "version: '0.1'\nsettings:\n  default_decision: allow\npolicies: []\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(policy)])
    # With allow-all policy, benign scenarios pass but adversarial won't be blocked → exit 1
    assert result.exit_code == 1
    assert str(policy) in result.output


def test_eval_json_output() -> None:
    """--json flag produces valid JSON on stdout."""
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(REFERENCE_POLICY), "--json"])
    assert result.exit_code == 0, f"stdout: {result.output}"
    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)


def test_eval_json_has_metrics() -> None:
    """JSON output contains expected metric keys."""
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(REFERENCE_POLICY), "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    metrics = parsed["metrics"]
    assert "benign_utility" in metrics
    assert "attack_success_rate" in metrics
    assert "false_positive_rate" in metrics
    assert "median_latency_ms" in metrics
    assert "all_passed" in metrics


def test_eval_missing_policy_exits_2() -> None:
    """--policy with nonexistent path → exit 2."""
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", "/nonexistent/path/policy.yaml"])
    assert result.exit_code == 2


def test_eval_bad_policy_exits_2(tmp_path: Path) -> None:
    """--policy with invalid YAML → exit 2."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid: yaml: policy", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(bad)])
    assert result.exit_code == 2


def test_eval_exit_1_on_failure(tmp_path: Path) -> None:
    """Policy that blocks everything → exit 1, FAIL in output."""
    policy = tmp_path / "block_all.yaml"
    policy.write_text(
        "version: '0.1'\nsettings:\n  default_decision: block\npolicies: []\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, ["eval", "--policy", str(policy)])
    assert result.exit_code == 1
    assert "FAIL" in result.output
