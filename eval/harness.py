"""Evaluation harness — runs scenarios against the AgentGate engine and collects results."""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from agentgate.engine import evaluate
from agentgate.models import ToolCall
from agentgate.policy import CompiledPolicy, load_and_compile
from agentgate.session import SessionStore


# ---------------------------------------------------------------------------
# Scenario definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioStep:
    """One tool call in a scenario sequence."""

    tool_name: str
    arguments: dict[str, Any]
    simulated_response: str | None = None
    expect_decision: Literal["allow", "block"] = "allow"
    description: str = ""


@dataclass(frozen=True)
class Scenario:
    """A complete evaluation scenario."""

    id: str
    name: str
    category: Literal["benign", "adversarial"]
    owasp_asi: str | None = None
    steps: list[ScenarioStep] = field(default_factory=list)
    policy_yaml: str | None = None
    description: str = ""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StepResult:
    """Result of evaluating one step."""

    step_index: int
    tool_name: str
    expected: Literal["allow", "block"]
    actual: Literal["allow", "block"]
    passed: bool
    matched_rule: str | None
    matched_detector: str | None
    message: str | None
    eval_time_ms: float


@dataclass(frozen=True)
class ScenarioResult:
    """Result of running one scenario."""

    scenario_id: str
    scenario_name: str
    category: Literal["benign", "adversarial"]
    owasp_asi: str | None
    step_results: list[StepResult]
    passed: bool
    utility_pass: bool
    security_pass: bool
    total_time_ms: float


@dataclass(frozen=True)
class EvalRun:
    """Complete evaluation run output."""

    timestamp: str
    policy_source: str
    scenario_count: int
    results: list[ScenarioResult]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_scenario(
    scenario: Scenario,
    default_policy: CompiledPolicy,
) -> ScenarioResult:
    """Run a single scenario against the engine. Returns structured result."""
    policy = default_policy

    # Resolve per-scenario policy override
    tmp_path: str | None = None
    if scenario.policy_yaml is not None:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        tmp_path = tmp.name
        try:
            tmp.write(scenario.policy_yaml)
            tmp.close()
            policy = load_and_compile(tmp_path)
        except Exception:
            os.unlink(tmp_path)
            raise

    try:
        session = SessionStore()
        step_results: list[StepResult] = []
        scenario_start = time.perf_counter()

        for i, step in enumerate(scenario.steps):
            tool_call = ToolCall(tool_name=step.tool_name, arguments=step.arguments)

            t0 = time.perf_counter()
            decision = evaluate(tool_call, policy, session)
            t1 = time.perf_counter()

            eval_time_ms = (t1 - t0) * 1000

            # Mirror proxy behaviour: only allowed calls get recorded in session
            if decision.action == "allow" and step.simulated_response is not None:
                entry = session.record_request(step.tool_name, step.arguments)
                session.record_response(entry, step.simulated_response)

            step_results.append(
                StepResult(
                    step_index=i,
                    tool_name=step.tool_name,
                    expected=step.expect_decision,
                    actual=decision.action,
                    passed=(decision.action == step.expect_decision),
                    matched_rule=decision.matched_rule,
                    matched_detector=decision.matched_detector,
                    message=decision.message,
                    eval_time_ms=eval_time_ms,
                )
            )

        total_time_ms = (time.perf_counter() - scenario_start) * 1000

        passed = all(sr.passed for sr in step_results)
        utility_pass = all(
            sr.actual == "allow" for sr in step_results if sr.expected == "allow"
        )
        security_pass = all(
            sr.actual == "block" for sr in step_results if sr.expected == "block"
        )

        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            category=scenario.category,
            owasp_asi=scenario.owasp_asi,
            step_results=step_results,
            passed=passed,
            utility_pass=utility_pass,
            security_pass=security_pass,
            total_time_ms=total_time_ms,
        )
    finally:
        if tmp_path is not None:
            os.unlink(tmp_path)


def run_all(
    scenarios: list[Scenario],
    default_policy: CompiledPolicy,
    policy_source: str = "default",
) -> EvalRun:
    """Run all scenarios. Returns complete evaluation run."""
    timestamp = datetime.now(timezone.utc).isoformat()
    results = [run_scenario(s, default_policy) for s in scenarios]
    return EvalRun(
        timestamp=timestamp,
        policy_source=policy_source,
        scenario_count=len(scenarios),
        results=results,
    )
