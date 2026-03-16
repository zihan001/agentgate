"""Tests for the 25 evaluation scenarios — structural validation and functional correctness."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentgate.policy import load_and_compile
from eval.harness import run_scenario
from eval.scenarios import ADVERSARIAL_SCENARIOS, ALL_SCENARIOS, BENIGN_SCENARIOS

REFERENCE_POLICY_PATH = Path(__file__).parent.parent / "eval" / "policies" / "eval_reference.yaml"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def reference_policy():
    return load_and_compile(str(REFERENCE_POLICY_PATH))


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


def test_scenario_count():
    assert len(BENIGN_SCENARIOS) == 10
    assert len(ADVERSARIAL_SCENARIOS) == 15
    assert len(ALL_SCENARIOS) == 25


def test_unique_ids():
    ids = [s.id for s in ALL_SCENARIOS]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"


def test_benign_ids_format():
    for s in BENIGN_SCENARIOS:
        assert re.fullmatch(r"B\d+", s.id), f"{s.id} does not match B\\d+"


def test_adversarial_ids_format():
    for s in ADVERSARIAL_SCENARIOS:
        assert re.fullmatch(r"A\d+", s.id), f"{s.id} does not match A\\d+"


def test_steps_nonempty():
    for s in ALL_SCENARIOS:
        assert len(s.steps) >= 1, f"Scenario {s.id} has no steps"


def test_tool_names_nonempty():
    for s in ALL_SCENARIOS:
        for i, step in enumerate(s.steps):
            assert step.tool_name, f"Scenario {s.id} step {i} has empty tool_name"


def test_valid_expect_decisions():
    for s in ALL_SCENARIOS:
        for i, step in enumerate(s.steps):
            assert step.expect_decision in (
                "allow",
                "block",
            ), f"Scenario {s.id} step {i}: invalid expect_decision '{step.expect_decision}'"


def test_reference_policy_loads():
    policy = load_and_compile(str(REFERENCE_POLICY_PATH))
    assert policy is not None
    assert policy.config.settings.default_decision == "allow"


# ---------------------------------------------------------------------------
# Functional validation — run scenarios through the engine
# ---------------------------------------------------------------------------


def test_all_scenarios_expected_decisions(reference_policy):
    """Run all 25 scenarios and verify every step matches its expected decision."""
    failures = []
    for scenario in ALL_SCENARIOS:
        result = run_scenario(scenario, reference_policy)
        if not result.passed:
            for sr in result.step_results:
                if not sr.passed:
                    failures.append(
                        f"{scenario.id} step {sr.step_index} ({sr.tool_name}): "
                        f"expected {sr.expected}, got {sr.actual}"
                        f" (rule={sr.matched_rule}, detector={sr.matched_detector},"
                        f" msg={sr.message})"
                    )
    assert not failures, "Scenario failures:\n" + "\n".join(failures)


def test_b7_no_false_positive(reference_policy):
    """B7: sensitive response + internal email must NOT trigger chain rule."""
    b7 = next(s for s in BENIGN_SCENARIOS if s.id == "B7")
    result = run_scenario(b7, reference_policy)
    assert result.passed, f"B7 failed — chain rule false positive: {result.step_results}"
    assert all(sr.actual == "allow" for sr in result.step_results)


def test_a11_chain_exfil(reference_policy):
    """A11: read_file with api_key → external email must be blocked by chain rule."""
    a11 = next(s for s in ADVERSARIAL_SCENARIOS if s.id == "A11")
    result = run_scenario(a11, reference_policy)
    assert result.step_results[0].actual == "allow", "A11 step 0 should be allowed"
    assert result.step_results[1].actual == "block", "A11 step 1 should be blocked"


def test_a12_chain_exfil_variant(reference_policy):
    """A12: read_file with password → external email must be blocked."""
    a12 = next(s for s in ADVERSARIAL_SCENARIOS if s.id == "A12")
    result = run_scenario(a12, reference_policy)
    assert result.step_results[0].actual == "allow", "A12 step 0 should be allowed"
    assert result.step_results[1].actual == "block", "A12 step 1 should be blocked"


def test_benign_utility_pass(reference_policy):
    """All benign scenarios must have utility_pass=True (all steps allowed)."""
    for scenario in BENIGN_SCENARIOS:
        result = run_scenario(scenario, reference_policy)
        assert result.utility_pass, f"{scenario.id} utility_pass=False: {result.step_results}"


def test_adversarial_security_pass(reference_policy):
    """All adversarial scenarios must have security_pass=True (attack steps blocked)."""
    for scenario in ADVERSARIAL_SCENARIOS:
        result = run_scenario(scenario, reference_policy)
        assert result.security_pass, (
            f"{scenario.id} security_pass=False: {result.step_results}"
        )
