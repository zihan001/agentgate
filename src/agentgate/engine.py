"""Rule evaluation engine — evaluates the decision stack: detectors, blocklist, allowlist, param rules, chain rules, default."""

from __future__ import annotations

from agentgate.models import Decision, ToolAllowRule, ToolBlockRule, ToolCall
from agentgate.policy import CompiledPolicy


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

    # --- Step 1: Detectors (Issue #26) ---
    # Will short-circuit here if any detector fires

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

    # --- Step 4: param_rule (Issue #8) ---
    # Will iterate param_rules top-to-bottom here

    # --- Step 5: chain_rule (Issue #11) ---
    # Will check session history here

    # --- Step 6: default decision ---
    return Decision(action=policy.config.settings.default_decision)
