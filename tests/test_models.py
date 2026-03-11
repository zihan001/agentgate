"""Tests for AgentGate data models."""

from agentgate.models import (
    AuditEntry,
    ChainRule,
    Decision,
    DetectorResult,
    ParamRule,
    PolicyConfig,
    ToolAllowRule,
    ToolBlockRule,
    ToolCall,
)
from datetime import datetime, timezone


class TestToolCall:
    def test_create_tool_call(self) -> None:
        tc = ToolCall(tool_name="read_file", arguments={"path": "/data/test.txt"}, call_id=1)
        assert tc.tool_name == "read_file"
        assert tc.arguments["path"] == "/data/test.txt"
        assert tc.call_id == 1

    def test_tool_call_optional_id(self) -> None:
        tc = ToolCall(tool_name="list_directory", arguments={})
        assert tc.call_id is None

    def test_tool_call_roundtrip(self) -> None:
        tc = ToolCall(tool_name="send_email", arguments={"to": "a@b.com", "body": "hello"})
        data = tc.model_dump()
        tc2 = ToolCall(**data)
        assert tc == tc2


class TestDecision:
    def test_allow_decision(self) -> None:
        d = Decision(action="allow")
        assert d.action == "allow"
        assert d.matched_rule is None

    def test_block_decision(self) -> None:
        d = Decision(
            action="block",
            matched_rule="sandboxed-files",
            matched_detector="path_traversal",
            message="Path outside allowed directory",
        )
        assert d.action == "block"
        assert d.matched_rule == "sandboxed-files"


class TestDetectorResult:
    def test_matched(self) -> None:
        r = DetectorResult(matched=True, detector_name="sql_injection", detail="DROP TABLE found")
        assert r.matched is True

    def test_not_matched(self) -> None:
        r = DetectorResult(matched=False, detector_name="ssrf")
        assert r.detail == ""


class TestAuditEntry:
    def test_create_entry(self) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            session_id="abc-123",
            tool_name="read_file",
            arguments='{"path": "/etc/passwd"}',
            decision="block",
            matched_rule="sandboxed-files",
            matched_detector="path_traversal",
            message="Path outside allowed directory",
            prev_hash="genesis",
            entry_hash="sha256abc",
        )
        assert entry.decision == "block"
        assert entry.id is None


class TestPolicyConfig:
    def test_minimal_config(self) -> None:
        config = PolicyConfig(version="0.1")
        assert config.settings.default_decision == "allow"
        assert config.detectors.sql_injection is True
        assert config.policies == []

    def test_config_with_rules(self) -> None:
        config = PolicyConfig(
            version="0.1",
            policies=[
                ToolAllowRule(name="allow-safe", type="tool_allow", tools=["read_file"]),
                ToolBlockRule(name="block-dangerous", type="tool_block", tools=["delete_file"]),
            ],
        )
        assert len(config.policies) == 2
        assert config.policies[0].type == "tool_allow"
        assert config.policies[1].type == "tool_block"

    def test_discriminated_union(self) -> None:
        """Verify that the discriminated union correctly picks the right model."""
        raw = {
            "version": "0.1",
            "policies": [
                {
                    "name": "sandbox",
                    "type": "param_rule",
                    "match": {"tool": "read_file"},
                    "check": {
                        "param": "path",
                        "op": "starts_with",
                        "value": "/data/",
                        "negate": True,
                    },
                    "message": "blocked",
                },
                {
                    "name": "chain",
                    "type": "chain_rule",
                    "window": 5,
                    "steps": [
                        {"tool": "read_file", "output_matches": "password"},
                        {"tool": "send_email"},
                    ],
                },
            ],
        }
        config = PolicyConfig(**raw)
        assert isinstance(config.policies[0], ParamRule)
        assert isinstance(config.policies[1], ChainRule)
