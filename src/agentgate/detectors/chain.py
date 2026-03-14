"""Chain detection logic — identifies unsafe tool-call sequences using session history window matching."""

from __future__ import annotations

from agentgate.models import ChainRule, ChainStep, Decision, ToolCall
from agentgate.policy import CompiledPolicy
from agentgate.session import SessionStore


def _match_step_against_entry(
    rule_name: str,
    step_index: int,
    step: ChainStep,
    entry_tool_name: str,
    entry_arguments: dict,
    entry_response_text: str | None,
    regexes: dict,
    *,
    check_output: bool = True,
) -> bool:
    """Check whether a single chain step matches a tool call or session entry."""
    if step.tool != entry_tool_name:
        return False

    if check_output and step.output_matches is not None:
        if entry_response_text is None:
            return False
        key = f"{rule_name}:steps.{step_index}.output_matches"
        pattern = regexes.get(key)
        if pattern is None or pattern.search(entry_response_text) is None:
            return False

    if step.param_matches is not None:
        for param_name in step.param_matches:
            key = f"{rule_name}:steps.{step_index}.param_matches.{param_name}"
            pattern = regexes.get(key)
            if pattern is None:
                return False
            val = entry_arguments.get(param_name)
            if val is None or pattern.search(str(val)) is None:
                return False

    return True


def evaluate_chain_rules(
    tool_call: ToolCall,
    policy: CompiledPolicy,
    session: SessionStore,
) -> Decision | None:
    """Evaluate chain rules against the current tool call and session history.

    Returns a block Decision if a chain rule matches, or None to let the
    engine fall through to the default decision.
    """
    chain_rules = [r for r in policy.config.policies if isinstance(r, ChainRule)]
    if not chain_rules:
        return None

    for rule in chain_rules:
        steps = rule.steps
        if not steps:
            continue

        last_step_index = len(steps) - 1
        last_step = steps[last_step_index]

        # Match last step against the incoming tool call (output_matches ignored)
        if not _match_step_against_entry(
            rule.name,
            last_step_index,
            last_step,
            tool_call.tool_name,
            tool_call.arguments,
            None,
            policy.regexes,
            check_output=False,
        ):
            continue

        # Match preceding steps against session history
        preceding_steps = steps[:last_step_index]
        if not preceding_steps:
            # Single-step rule: last step matched, so block
            return Decision(
                action="block",
                matched_rule=rule.name,
                message=rule.message,
            )

        history = session.recent(rule.window)
        scan_start = 0
        all_matched = True

        for step_index, step in enumerate(preceding_steps):
            found = False
            for j in range(scan_start, len(history)):
                entry = history[j]
                if _match_step_against_entry(
                    rule.name,
                    step_index,
                    step,
                    entry.tool_name,
                    entry.arguments,
                    entry.response_text,
                    policy.regexes,
                ):
                    scan_start = j + 1
                    found = True
                    break
            if not found:
                all_matched = False
                break

        if all_matched:
            return Decision(
                action="block",
                matched_rule=rule.name,
                message=rule.message,
            )

    return None
