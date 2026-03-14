"""Rule evaluation engine — evaluates the decision stack: detectors, blocklist, allowlist, param rules, chain rules, default."""

from __future__ import annotations

import re
from typing import Any

from agentgate.detectors import run_all as run_detectors
from agentgate.models import Decision, ParamRule, ToolAllowRule, ToolBlockRule, ToolCall
from agentgate.policy import CompiledPolicy

_MISSING = object()


def _resolve_param(arguments: dict[str, Any], param_path: str) -> Any:
    """Resolve a dotted param path against the tool call arguments dict.

    Returns the leaf value, or _MISSING if any key is absent or an
    intermediate value is not a dict.
    """
    current: Any = arguments
    for key in param_path.split("."):
        if not isinstance(current, dict) or key not in current:
            return _MISSING
        current = current[key]
    return current


def _eval_param_check(
    param_value: Any,
    check: "ParamRule.check.__class__",
    compiled_regexes: dict[str, re.Pattern],
    rule_name: str,
) -> bool:
    """Return True if the param check means the call should be blocked."""
    val = str(param_value)
    op = check.op

    if op == "equals":
        condition_met = val == check.value
    elif op == "starts_with":
        condition_met = val.startswith(check.value)
    elif op == "ends_with":
        condition_met = val.endswith(check.value)
    elif op == "contains":
        condition_met = check.value in val
    elif op == "matches":
        regex_key = f"{rule_name}:check.value"
        pattern = compiled_regexes.get(regex_key)
        condition_met = pattern.search(val) is not None if pattern else False
    elif op == "in":
        condition_met = val in check.value
    else:
        condition_met = False

    return condition_met ^ check.negate


def evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision:
    """Evaluate a tool call against the compiled policy and return a decision.

    Decision stack (evaluated top-to-bottom, first match wins):
      1. Detectors  — short-circuit on match
      2. tool_block — block if tool is on any blocklist
      3. tool_allow — block if any allowlist exists and tool is absent
      4. param_rule — block if parameter check fails
      5. chain_rule — block if sequential pattern detected
      6. default    — fallthrough to policy default_decision
    """
    rules = policy.config.policies

    # --- Step 1: Detectors ---
    detector_results = run_detectors(tool_call, policy.config.detectors.model_dump())
    if detector_results:
        first = detector_results[0]
        return Decision(
            action="block",
            matched_detector=first.detector_name,
            message=first.detail,
        )

    # --- Step 2: tool_block ---
    block_rules = [r for r in rules if isinstance(r, ToolBlockRule)]
    blocked_tools: set[str] = set()
    for rule in block_rules:
        blocked_tools.update(rule.tools)

    if tool_call.tool_name in blocked_tools:
        first_match = next(r for r in block_rules if tool_call.tool_name in r.tools)
        return Decision(
            action="block",
            matched_rule=first_match.name,
            message=f"Tool '{tool_call.tool_name}' is blocked by policy",
        )

    # --- Step 3: tool_allow ---
    allow_rules = [r for r in rules if isinstance(r, ToolAllowRule)]
    if allow_rules:
        allowed_tools: set[str] = set()
        for rule in allow_rules:
            allowed_tools.update(rule.tools)

        if tool_call.tool_name not in allowed_tools:
            return Decision(
                action="block",
                matched_rule=allow_rules[0].name,
                message=f"Tool '{tool_call.tool_name}' is not on the allowlist",
            )

    # --- Step 4: param_rule ---
    param_rules = [r for r in rules if isinstance(r, ParamRule)]
    for rule in param_rules:
        if rule.match.tool != "*" and rule.match.tool != tool_call.tool_name:
            continue

        value = _resolve_param(tool_call.arguments, rule.check.param)
        if value is _MISSING:
            continue

        if _eval_param_check(value, rule.check, policy.regexes, rule.name):
            return Decision(
                action="block",
                matched_rule=rule.name,
                message=rule.message or f"Blocked by param_rule '{rule.name}'",
            )

    # --- Step 5: chain_rule (Issue #11) ---
    # Will check session history here

    # --- Step 6: default decision ---
    return Decision(action=policy.config.settings.default_decision)
