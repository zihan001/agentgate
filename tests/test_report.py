"""Tests for eval/report.py — metric computation and formatting."""

from __future__ import annotations

import json

import pytest

from eval.harness import EvalRun, ScenarioResult, StepResult
from eval.report import compute_metrics, format_json, format_table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_step(
    *,
    expected: str = "allow",
    actual: str = "allow",
    eval_time_ms: float = 0.05,
    step_index: int = 0,
) -> StepResult:
    return StepResult(
        step_index=step_index,
        tool_name="test_tool",
        expected=expected,
        actual=actual,
        passed=(expected == actual),
        matched_rule=None,
        matched_detector=None,
        message=None,
        eval_time_ms=eval_time_ms,
    )


def _make_scenario(
    scenario_id: str,
    category: str,
    *,
    passed: bool = True,
    utility_pass: bool = True,
    security_pass: bool = True,
    step_latencies: list[float] | None = None,
) -> ScenarioResult:
    if step_latencies is None:
        step_latencies = [0.05]

    expected = "allow" if category == "benign" else "block"
    actual = expected if passed else ("block" if expected == "allow" else "allow")

    steps = [
        _make_step(
            expected=expected,
            actual=actual,
            eval_time_ms=lat,
            step_index=i,
        )
        for i, lat in enumerate(step_latencies)
    ]

    return ScenarioResult(
        scenario_id=scenario_id,
        scenario_name=f"Test scenario {scenario_id}",
        category=category,
        owasp_asi=None,
        step_results=steps,
        passed=passed,
        utility_pass=utility_pass,
        security_pass=security_pass,
        total_time_ms=sum(step_latencies),
    )


def _make_eval_run(results: list[ScenarioResult]) -> EvalRun:
    return EvalRun(
        timestamp="2026-03-16T00:00:00+00:00",
        policy_source="test_policy.yaml",
        scenario_count=len(results),
        results=results,
    )


def _perfect_run() -> EvalRun:
    """10 benign pass + 15 adversarial pass."""
    results = [_make_scenario(f"B{i}", "benign") for i in range(1, 11)] + [
        _make_scenario(f"A{i}", "adversarial") for i in range(1, 16)
    ]
    return _make_eval_run(results)


# ---------------------------------------------------------------------------
# compute_metrics tests
# ---------------------------------------------------------------------------


def test_compute_metrics_perfect_run() -> None:
    m = compute_metrics(_perfect_run())
    assert m.benign_utility == 1.0
    assert m.attack_success_rate == 0.0
    assert m.false_positive_rate == 0.0
    assert m.all_passed is True
    assert m.benign_total == 10
    assert m.adversarial_total == 15


def test_compute_metrics_one_benign_failure() -> None:
    results = (
        [_make_scenario(f"B{i}", "benign") for i in range(1, 10)]
        + [
            _make_scenario("B10", "benign", passed=False, utility_pass=False),
        ]
        + [_make_scenario(f"A{i}", "adversarial") for i in range(1, 16)]
    )
    m = compute_metrics(_make_eval_run(results))
    assert m.benign_utility == pytest.approx(0.9)
    assert m.false_positive_rate == pytest.approx(0.1)
    assert m.all_passed is False


def test_compute_metrics_one_adversarial_failure() -> None:
    results = (
        [_make_scenario(f"B{i}", "benign") for i in range(1, 11)]
        + [_make_scenario(f"A{i}", "adversarial") for i in range(1, 15)]
        + [
            _make_scenario("A15", "adversarial", passed=False, security_pass=False),
        ]
    )
    m = compute_metrics(_make_eval_run(results))
    assert m.attack_success_rate == pytest.approx(1.0 / 15)
    assert m.all_passed is False


def test_compute_metrics_all_fail() -> None:
    results = [
        _make_scenario(f"B{i}", "benign", passed=False, utility_pass=False) for i in range(1, 11)
    ] + [
        _make_scenario(f"A{i}", "adversarial", passed=False, security_pass=False)
        for i in range(1, 16)
    ]
    m = compute_metrics(_make_eval_run(results))
    assert m.benign_utility == 0.0
    assert m.attack_success_rate == 1.0
    assert m.false_positive_rate == 1.0


def test_compute_metrics_empty_benign() -> None:
    results = [_make_scenario(f"A{i}", "adversarial") for i in range(1, 4)]
    m = compute_metrics(_make_eval_run(results))
    assert m.benign_utility is None
    assert m.false_positive_rate is None
    assert m.benign_total == 0
    assert m.attack_success_rate == 0.0


def test_compute_metrics_empty_adversarial() -> None:
    results = [_make_scenario(f"B{i}", "benign") for i in range(1, 4)]
    m = compute_metrics(_make_eval_run(results))
    assert m.attack_success_rate is None
    assert m.adversarial_total == 0
    assert m.benign_utility == 1.0


def test_compute_metrics_median_latency() -> None:
    results = [
        _make_scenario("B1", "benign", step_latencies=[1.0, 3.0, 5.0]),
        _make_scenario("A1", "adversarial", step_latencies=[2.0, 4.0]),
    ]
    m = compute_metrics(_make_eval_run(results))
    # Values: [1.0, 3.0, 5.0, 2.0, 4.0] → sorted: [1.0, 2.0, 3.0, 4.0, 5.0] → median = 3.0
    assert m.median_latency_ms == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# format_table tests
# ---------------------------------------------------------------------------


def test_format_table_contains_metrics() -> None:
    run = _perfect_run()
    m = compute_metrics(run)
    table = format_table(run, m, "test_policy.yaml")

    assert "Benign Utility (BU)" in table
    assert "Attack Success Rate (ASR)" in table
    assert "False Positive Rate (FPR)" in table
    assert "Median Latency" in table
    assert "PASS" in table
    assert "test_policy.yaml" in table
    assert "(10/10)" in table
    assert "(0/15)" in table


# ---------------------------------------------------------------------------
# format_json tests
# ---------------------------------------------------------------------------


def test_format_json_valid() -> None:
    run = _perfect_run()
    m = compute_metrics(run)
    output = format_json(run, m)
    parsed = json.loads(output)

    assert "timestamp" in parsed
    assert "policy_source" in parsed
    assert "scenario_count" in parsed
    assert "metrics" in parsed
    assert "results" in parsed


def test_format_json_metrics_match() -> None:
    run = _perfect_run()
    m = compute_metrics(run)
    output = format_json(run, m)
    parsed = json.loads(output)

    assert parsed["metrics"]["benign_utility"] == m.benign_utility
    assert parsed["metrics"]["attack_success_rate"] == m.attack_success_rate
    assert parsed["metrics"]["false_positive_rate"] == m.false_positive_rate
    assert parsed["metrics"]["median_latency_ms"] == pytest.approx(m.median_latency_ms)
    assert parsed["metrics"]["all_passed"] == m.all_passed
