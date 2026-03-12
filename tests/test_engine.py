"""Tests for rule evaluation engine logic."""

from agentgate.engine import evaluate
from agentgate.models import (
    PolicyConfig,
    Settings,
    ToolAllowRule,
    ToolBlockRule,
    ToolCall,
)
from agentgate.policy import CompiledPolicy


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
