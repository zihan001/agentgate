"""Tests for rule evaluation engine logic."""

import re

from agentgate.engine import evaluate
from agentgate.models import (
    ChainRule,
    ChainStep,
    PolicyConfig,
    Settings,
    ToolAllowRule,
    ToolBlockRule,
    ToolCall,
)
from agentgate.policy import CompiledPolicy
from agentgate.session import SessionStore


def _make_policy(
    default_decision: str = "allow",
    policies: list | None = None,
) -> CompiledPolicy:
    """Build a CompiledPolicy from keyword args. Shortcut for tests."""
    config = PolicyConfig(
        version="0.1",
        settings=Settings(default_decision=default_decision),
        policies=policies or [],
    )
    return CompiledPolicy(config=config, regexes={})


def _call(tool_name: str = "read_file") -> ToolCall:
    """Build a ToolCall with sensible defaults."""
    return ToolCall(tool_name=tool_name, arguments={})


# --- Default decision tests ---


def test_allow_by_default():
    policy = _make_policy(default_decision="allow")
    decision = evaluate(_call("read_file"), policy)
    assert decision.action == "allow"
    assert decision.matched_rule is None


def test_block_by_default():
    policy = _make_policy(default_decision="block")
    decision = evaluate(_call("read_file"), policy)
    assert decision.action == "block"
    assert decision.matched_rule is None


# --- Allowlist tests ---


def test_tool_on_allowlist_allowed():
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="safe-tools", type="tool_allow", tools=["read_file", "write_file"]),
        ],
    )
    decision = evaluate(_call("read_file"), policy)
    assert decision.action == "allow"


def test_tool_not_on_allowlist_blocked():
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="safe-tools", type="tool_allow", tools=["read_file", "write_file"]),
        ],
    )
    decision = evaluate(_call("delete_file"), policy)
    assert decision.action == "block"
    assert decision.matched_rule == "safe-tools"
    assert "not on the allowlist" in decision.message


# --- Blocklist tests ---


def test_tool_on_blocklist_blocked():
    policy = _make_policy(
        policies=[
            ToolBlockRule(
                name="dangerous-tools", type="tool_block", tools=["delete_file", "execute_shell"]
            ),
        ],
    )
    decision = evaluate(_call("delete_file"), policy)
    assert decision.action == "block"
    assert decision.matched_rule == "dangerous-tools"
    assert "blocked" in decision.message


def test_tool_not_on_blocklist_allowed():
    policy = _make_policy(
        default_decision="allow",
        policies=[
            ToolBlockRule(
                name="dangerous-tools", type="tool_block", tools=["delete_file", "execute_shell"]
            ),
        ],
    )
    decision = evaluate(_call("read_file"), policy)
    assert decision.action == "allow"


# --- Precedence tests ---


def test_blocklist_beats_allowlist():
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="safe-tools", type="tool_allow", tools=["read_file", "delete_file"]),
            ToolBlockRule(name="no-delete", type="tool_block", tools=["delete_file"]),
        ],
    )
    decision = evaluate(_call("delete_file"), policy)
    assert decision.action == "block"
    assert decision.matched_rule == "no-delete"


# --- Merging tests ---


def test_multiple_allowlist_rules_merge():
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="read-tools", type="tool_allow", tools=["read_file"]),
            ToolAllowRule(name="write-tools", type="tool_allow", tools=["write_file"]),
        ],
    )
    decision = evaluate(_call("write_file"), policy)
    assert decision.action == "allow"


def test_multiple_blocklist_rules_merge():
    policy = _make_policy(
        policies=[
            ToolBlockRule(name="no-delete", type="tool_block", tools=["delete_file"]),
            ToolBlockRule(name="no-shell", type="tool_block", tools=["execute_shell"]),
        ],
    )
    decision = evaluate(_call("execute_shell"), policy)
    assert decision.action == "block"


# --- No-allowlist fallthrough test ---


def test_no_allowlist_means_all_tools_pass_to_default():
    policy = _make_policy(
        default_decision="allow",
        policies=[
            ToolBlockRule(name="no-delete", type="tool_block", tools=["delete_file"]),
        ],
    )
    decision = evaluate(_call("anything_else"), policy)
    assert decision.action == "allow"


# --- Detector integration tests (Issue #26) ---


def _call_with_args(tool_name: str = "read_file", arguments: dict | None = None) -> ToolCall:
    return ToolCall(tool_name=tool_name, arguments=arguments or {})


def test_detector_blocks_even_when_tool_on_allowlist():
    """Detectors (Step 1) take precedence over tool_allow (Step 3)."""
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="safe-tools", type="tool_allow", tools=["read_file"]),
        ],
    )
    tc = _call_with_args("read_file", {"path": "../../etc/passwd"})
    decision = evaluate(tc, policy)
    assert decision.action == "block"
    assert decision.matched_detector is not None
    assert decision.matched_rule is None


def test_detector_blocks_with_default_allow_no_rules():
    """Detectors fire before the default decision, even with no policy rules."""
    policy = _make_policy(default_decision="allow")
    tc = _call_with_args("any_tool", {"key": "AKIA1234567890ABCDEF"})
    decision = evaluate(tc, policy)
    assert decision.action == "block"
    assert decision.matched_detector == "secrets_in_params"


def test_detector_block_returns_matched_detector_not_matched_rule():
    """A detector block populates matched_detector, not matched_rule."""
    policy = _make_policy(default_decision="allow")
    tc = _call_with_args("tool", {"query": "DROP TABLE users"})
    decision = evaluate(tc, policy)
    assert decision.action == "block"
    assert decision.matched_detector == "sql_injection"
    assert decision.matched_rule is None
    assert decision.message is not None


def test_clean_call_passes_detectors_and_allowlist():
    """A clean tool call passes both detectors and allowlist."""
    policy = _make_policy(
        policies=[
            ToolAllowRule(name="safe-tools", type="tool_allow", tools=["read_file"]),
        ],
    )
    tc = _call_with_args("read_file", {"text": "hello world"})
    decision = evaluate(tc, policy)
    assert decision.action == "allow"


# --- Chain rule engine integration tests (Issue #11) ---


def _make_chain_policy() -> tuple[CompiledPolicy, ChainRule]:
    """Build a policy with a chain rule for engine tests."""
    rule = ChainRule(
        name="block-exfil",
        type="chain_rule",
        window=5,
        steps=[
            ChainStep(tool="read_file", output_matches=r"SENSITIVE"),
            ChainStep(tool="send_email"),
        ],
        message="Blocked exfil",
    )
    config = PolicyConfig(
        version="0.1",
        settings=Settings(default_decision="allow"),
        policies=[rule],
    )
    regexes = {
        f"{rule.name}:steps.0.output_matches": re.compile(r"SENSITIVE", re.IGNORECASE),
    }
    return CompiledPolicy(config=config, regexes=regexes), rule


def test_engine_chain_rule_blocks():
    """evaluate() with session containing matching history blocks via chain rule."""
    policy, _ = _make_chain_policy()
    session = SessionStore()
    entry = session.record_request("read_file", {"path": "/x"})
    session.record_response(entry, "data with SENSITIVE content")

    decision = evaluate(
        ToolCall(tool_name="send_email", arguments={}), policy, session
    )
    assert decision.action == "block"
    assert decision.matched_rule == "block-exfil"


def test_engine_chain_rule_skipped_no_session():
    """evaluate() with session=None skips chain rules and uses default decision."""
    policy, _ = _make_chain_policy()

    decision = evaluate(
        ToolCall(tool_name="send_email", arguments={}), policy
    )
    assert decision.action == "allow"
    assert decision.matched_rule is None


def test_engine_detector_beats_chain():
    """Detector (step 1) fires before chain rule (step 5)."""
    policy, _ = _make_chain_policy()
    session = SessionStore()
    entry = session.record_request("read_file", {"path": "/x"})
    session.record_response(entry, "SENSITIVE data")

    # Tool call with path traversal in arguments — triggers detector
    decision = evaluate(
        ToolCall(tool_name="send_email", arguments={"path": "../../etc/passwd"}),
        policy,
        session,
    )
    assert decision.action == "block"
    assert decision.matched_detector is not None
    assert decision.matched_rule is None
