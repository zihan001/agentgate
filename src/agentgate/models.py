"""Pydantic data models — defines the contract between all AgentGate modules."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


# --- Tool call and decision models ---


class ToolCall(BaseModel):
    """A parsed MCP tool call extracted from a JSON-RPC request."""

    tool_name: str
    arguments: dict[str, Any]
    call_id: str | int | None = None


class Decision(BaseModel):
    """The result of evaluating a tool call against the policy."""

    action: Literal["allow", "block"]
    matched_rule: str | None = None
    matched_detector: str | None = None
    message: str | None = None


class DetectorResult(BaseModel):
    """The result of a single detector's evaluation."""

    matched: bool
    detector_name: str
    detail: str = ""


# --- Audit models ---


class AuditEntry(BaseModel):
    """A single entry in the append-only audit log."""

    id: int | None = None
    timestamp: datetime
    session_id: str
    tool_name: str
    arguments: str  # JSON string
    decision: Literal["allow", "block"]
    matched_rule: str | None = None
    matched_detector: str | None = None
    message: str | None = None
    prev_hash: str
    entry_hash: str


# --- Policy configuration models ---


class Settings(BaseModel):
    """Global policy settings."""

    default_decision: Literal["allow", "block"] = "allow"
    log_level: Literal["debug", "info", "warn", "error"] = "info"


class DetectorsConfig(BaseModel):
    """Toggle built-in detectors on/off."""

    model_config = ConfigDict(extra="forbid")

    sql_injection: bool = True
    path_traversal: bool = True
    command_injection: bool = True
    ssrf_private_ip: bool = True
    secrets_in_params: bool = True


class ToolAllowRule(BaseModel):
    """Allowlist rule — only listed tools may be called."""

    name: str
    type: Literal["tool_allow"]
    tools: list[str]


class ToolBlockRule(BaseModel):
    """Blocklist rule — listed tools are always blocked."""

    name: str
    type: Literal["tool_block"]
    tools: list[str]


class ParamCheck(BaseModel):
    """Parameter check definition for a param_rule."""

    param: str
    op: Literal["equals", "starts_with", "ends_with", "contains", "matches", "in"]
    value: str | list[str]
    negate: bool = False


class ParamMatch(BaseModel):
    """Match criteria for a param_rule."""

    tool: str


class ParamRule(BaseModel):
    """Parameter pattern matching rule."""

    name: str
    type: Literal["param_rule"]
    match: ParamMatch
    check: ParamCheck
    message: str = ""


class ChainStep(BaseModel):
    """A single step in a chain rule definition."""

    tool: str
    output_matches: str | None = None
    param_matches: dict[str, str] | None = None


class ChainRule(BaseModel):
    """Sequential tool-call detection rule."""

    name: str
    type: Literal["chain_rule"]
    window: int = 10
    steps: list[ChainStep]
    message: str = ""


RuleConfig = Annotated[
    Union[ToolAllowRule, ToolBlockRule, ParamRule, ChainRule],
    Field(discriminator="type"),
]


class PolicyConfig(BaseModel):
    """Top-level policy configuration loaded from agentgate.yaml."""

    version: str
    settings: Settings = Settings()
    detectors: DetectorsConfig = DetectorsConfig()
    policies: list[RuleConfig] = []
