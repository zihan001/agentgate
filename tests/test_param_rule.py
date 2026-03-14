"""Tests for param_rule evaluation (Issue #8)."""

import re

from agentgate.engine import evaluate
from agentgate.models import (
    ParamCheck,
    ParamMatch,
    ParamRule,
    PolicyConfig,
    Settings,
    ToolBlockRule,
    ToolCall,
)
from agentgate.policy import CompiledPolicy


def _make_policy(
    param_rules: list[ParamRule] | None = None,
    default_decision: str = "allow",
    policies: list | None = None,
    regexes: dict[str, re.Pattern] | None = None,
) -> CompiledPolicy:
    """Build a CompiledPolicy with param_rules."""
    all_policies = list(policies or [])
    all_policies.extend(param_rules or [])
    config = PolicyConfig(
        version="0.1",
        settings=Settings(default_decision=default_decision),
        policies=all_policies,
    )
    return CompiledPolicy(config=config, regexes=regexes or {})


def _param_rule(
    name: str = "test-rule",
    tool: str = "read_file",
    param: str = "path",
    op: str = "equals",
    value: str | list[str] = "",
    negate: bool = False,
    message: str = "",
) -> ParamRule:
    """Build a ParamRule with sensible defaults."""
    return ParamRule(
        name=name,
        type="param_rule",
        match=ParamMatch(tool=tool),
        check=ParamCheck(param=param, op=op, value=value, negate=negate),
        message=message,
    )


def _call(tool_name: str = "read_file", arguments: dict | None = None) -> ToolCall:
    return ToolCall(tool_name=tool_name, arguments=arguments or {})


# --- Operator tests (12) ---


def test_equals_match():
    policy = _make_policy(param_rules=[_param_rule(op="equals", value="production", param="env")])
    decision = evaluate(_call("read_file", {"env": "production"}), policy)
    assert decision.action == "block"


def test_equals_no_match():
    policy = _make_policy(param_rules=[_param_rule(op="equals", value="production", param="env")])
    decision = evaluate(_call("read_file", {"env": "staging"}), policy)
    assert decision.action == "allow"


def test_starts_with_match():
    policy = _make_policy(param_rules=[_param_rule(op="starts_with", value="/data/")])
    decision = evaluate(_call("read_file", {"path": "/data/file.txt"}), policy)
    assert decision.action == "block"


def test_starts_with_no_match():
    policy = _make_policy(param_rules=[_param_rule(op="starts_with", value="/data/")])
    decision = evaluate(_call("read_file", {"path": "/home/user/file.txt"}), policy)
    assert decision.action == "allow"


def test_ends_with_match():
    policy = _make_policy(param_rules=[_param_rule(op="ends_with", value=".exe", param="filename")])
    decision = evaluate(_call("read_file", {"filename": "malware.exe"}), policy)
    assert decision.action == "block"


def test_ends_with_no_match():
    policy = _make_policy(param_rules=[_param_rule(op="ends_with", value=".exe", param="filename")])
    decision = evaluate(_call("read_file", {"filename": "report.csv"}), policy)
    assert decision.action == "allow"


def test_contains_match():
    policy = _make_policy(param_rules=[_param_rule(op="contains", value="password", param="text")])
    decision = evaluate(_call("read_file", {"text": "my_password_123"}), policy)
    assert decision.action == "block"


def test_contains_no_match():
    policy = _make_policy(param_rules=[_param_rule(op="contains", value="password", param="text")])
    decision = evaluate(_call("read_file", {"text": "normal text"}), policy)
    assert decision.action == "allow"


def test_matches_match():
    rule = _param_rule(name="email-check", op="matches", value=r".*@evil\.com$", param="to")
    regexes = {"email-check:check.value": re.compile(r".*@evil\.com$")}
    policy = _make_policy(param_rules=[rule], regexes=regexes)
    decision = evaluate(_call("read_file", {"to": "hacker@evil.com"}), policy)
    assert decision.action == "block"


def test_matches_no_match():
    rule = _param_rule(name="email-check", op="matches", value=r".*@evil\.com$", param="to")
    regexes = {"email-check:check.value": re.compile(r".*@evil\.com$")}
    policy = _make_policy(param_rules=[rule], regexes=regexes)
    decision = evaluate(_call("read_file", {"to": "user@safe.com"}), policy)
    assert decision.action == "allow"


def test_in_match():
    policy = _make_policy(
        param_rules=[_param_rule(op="in", value=["delete", "drop"], param="action")]
    )
    decision = evaluate(_call("read_file", {"action": "delete"}), policy)
    assert decision.action == "block"


def test_in_no_match():
    policy = _make_policy(
        param_rules=[_param_rule(op="in", value=["delete", "drop"], param="action")]
    )
    decision = evaluate(_call("read_file", {"action": "select"}), policy)
    assert decision.action == "allow"


# --- Negate tests (4) ---


def test_negate_true_blocks_when_not_met():
    """negate=True: block when path does NOT start with /data/."""
    policy = _make_policy(param_rules=[_param_rule(op="starts_with", value="/data/", negate=True)])
    decision = evaluate(_call("read_file", {"path": "/home/user/file.txt"}), policy)
    assert decision.action == "block"


def test_negate_true_allows_when_met():
    """negate=True: allow when path starts with /data/ (condition met, negated = no block)."""
    policy = _make_policy(param_rules=[_param_rule(op="starts_with", value="/data/", negate=True)])
    decision = evaluate(_call("read_file", {"path": "/data/file.txt"}), policy)
    assert decision.action == "allow"


def test_negate_false_blocks_when_met():
    policy = _make_policy(
        param_rules=[_param_rule(op="contains", value="DROP", param="query", negate=False)]
    )
    decision = evaluate(_call("read_file", {"query": "DROP TABLE"}), policy)
    assert decision.action == "block"


def test_negate_false_allows_when_not_met():
    policy = _make_policy(
        param_rules=[_param_rule(op="contains", value="DROP", param="query", negate=False)]
    )
    decision = evaluate(_call("read_file", {"query": "SELECT *"}), policy)
    assert decision.action == "allow"


# --- Param resolution tests (4) ---


def test_missing_param_skips():
    """Rule is skipped (allow) when the checked param doesn't exist."""
    policy = _make_policy(param_rules=[_param_rule(op="equals", value="bad")])
    decision = evaluate(_call("read_file", {"other_key": "value"}), policy)
    assert decision.action == "allow"


def test_nested_param_dot_notation():
    """Dot-notation resolves nested dict keys."""
    policy = _make_policy(
        param_rules=[_param_rule(op="equals", value="true", param="options.recursive")]
    )
    decision = evaluate(_call("read_file", {"options": {"recursive": "true"}}), policy)
    assert decision.action == "block"


def test_nested_param_missing_intermediate():
    """Missing intermediate key in dot path → skip rule."""
    policy = _make_policy(
        param_rules=[_param_rule(op="equals", value="true", param="options.recursive")]
    )
    decision = evaluate(_call("read_file", {"path": "/data"}), policy)
    assert decision.action == "allow"


def test_param_value_is_none():
    """None param value is coerced to 'None' string."""
    policy = _make_policy(param_rules=[_param_rule(op="equals", value="None", param="path")])
    decision = evaluate(_call("read_file", {"path": None}), policy)
    assert decision.action == "block"


# --- Tool match tests (2) ---


def test_tool_matches_evaluates():
    policy = _make_policy(param_rules=[_param_rule(tool="read_file", op="equals", value="bad")])
    decision = evaluate(_call("read_file", {"path": "bad"}), policy)
    assert decision.action == "block"


def test_tool_mismatch_skips():
    policy = _make_policy(param_rules=[_param_rule(tool="read_file", op="equals", value="bad")])
    decision = evaluate(_call("send_email", {"path": "bad"}), policy)
    assert decision.action == "allow"


# --- Integration / precedence tests (4) ---


def test_detector_beats_param_rule():
    """Detector (Step 1) fires before param_rule (Step 4)."""
    policy = _make_policy(param_rules=[_param_rule(op="equals", value="../../etc/passwd")])
    decision = evaluate(_call("read_file", {"path": "../../etc/passwd"}), policy)
    assert decision.action == "block"
    assert decision.matched_detector is not None
    assert decision.matched_rule is None


def test_blocklist_beats_param_rule():
    """Blocklist (Step 2) fires before param_rule (Step 4)."""
    policy = _make_policy(
        policies=[
            ToolBlockRule(name="no-read", type="tool_block", tools=["read_file"]),
        ],
        param_rules=[_param_rule(op="equals", value="anything")],
    )
    decision = evaluate(_call("read_file", {"path": "anything"}), policy)
    assert decision.action == "block"
    assert decision.matched_rule == "no-read"


def test_param_rule_first_match_wins():
    """When two param_rules match, the first one's message is used."""
    policy = _make_policy(
        param_rules=[
            _param_rule(name="rule-A", op="contains", value="bad", param="text", message="A"),
            _param_rule(name="rule-B", op="contains", value="bad", param="text", message="B"),
        ]
    )
    decision = evaluate(_call("read_file", {"text": "bad stuff"}), policy)
    assert decision.action == "block"
    assert decision.matched_rule == "rule-A"
    assert decision.message == "A"


def test_param_rule_block_then_default_allow():
    """Param rule blocks bad path; good path falls through to default allow."""
    rule = _param_rule(op="starts_with", value="/data/", negate=True, message="sandbox")
    policy = _make_policy(param_rules=[rule])

    bad = evaluate(_call("read_file", {"path": "/home/user/file.txt"}), policy)
    assert bad.action == "block"
    assert bad.message == "sandbox"

    good = evaluate(_call("read_file", {"path": "/data/report.csv"}), policy)
    assert good.action == "allow"
