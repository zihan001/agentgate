"""Tests for YAML policy loading, validation, and regex compilation."""

import re

import pytest

from agentgate.models import (
    ChainRule,
    ChainStep,
    ParamCheck,
    ParamMatch,
    ParamRule,
    PolicyConfig,
    ToolAllowRule,
    ToolBlockRule,
)
from agentgate.policy import (
    CompiledPolicy,
    PolicyLoadError,
    compile_regexes,
    load_policy,
)


# --- Helpers ---

MINIMAL_YAML = 'version: "0.1"\n'

FULL_YAML = """\
version: "0.1"

settings:
  default_decision: allow
  log_level: info

detectors:
  sql_injection: true
  path_traversal: true
  command_injection: true
  ssrf_private_ip: true
  secrets_in_params: true

policies:
  - name: only-safe-tools
    type: tool_allow
    tools:
      - read_file
      - write_file
      - list_directory
      - send_email

  - name: no-destructive-ops
    type: tool_block
    tools:
      - delete_file
      - execute_shell

  - name: sandboxed-files
    type: param_rule
    match:
      tool: read_file
    check:
      param: path
      op: starts_with
      value: "/data/workspace/"
      negate: true
    message: "File access restricted to /data/workspace/"

  - name: internal-email-only
    type: param_rule
    match:
      tool: send_email
    check:
      param: to
      op: matches
      value: ".*@mycompany\\\\.com$"
      negate: true
    message: "Emails may only be sent to @mycompany.com addresses"

  - name: block-exfil-after-sensitive-read
    type: chain_rule
    window: 5
    steps:
      - tool: read_file
        output_matches: "BEGIN.*PRIVATE KEY|password|api[_-]?key"
      - tool: send_email
        param_matches:
          to: "^(?!.*@mycompany\\\\.com$).*$"
    message: "Blocked: sending email after reading sensitive data"
"""


def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "agentgate.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


# --- load_policy tests ---


def test_load_minimal_policy(tmp_path):
    path = _write_yaml(tmp_path, MINIMAL_YAML)
    config = load_policy(path)

    assert isinstance(config, PolicyConfig)
    assert config.version == "0.1"
    assert config.settings.default_decision == "allow"
    assert config.settings.log_level == "info"
    assert config.detectors.sql_injection is True
    assert config.policies == []


def test_load_full_policy(tmp_path):
    path = _write_yaml(tmp_path, FULL_YAML)
    config = load_policy(path)

    assert config.version == "0.1"
    assert config.settings.default_decision == "allow"
    assert len(config.policies) == 5
    assert isinstance(config.policies[0], ToolAllowRule)
    assert isinstance(config.policies[1], ToolBlockRule)
    assert isinstance(config.policies[2], ParamRule)
    assert isinstance(config.policies[3], ParamRule)
    assert isinstance(config.policies[4], ChainRule)


def test_load_file_not_found():
    with pytest.raises(PolicyLoadError, match="not found"):
        load_policy("/nonexistent/path/agentgate.yaml")


def test_load_invalid_yaml(tmp_path):
    path = _write_yaml(tmp_path, "policies: [{{invalid")
    with pytest.raises(PolicyLoadError, match="Failed to parse YAML"):
        load_policy(path)


def test_load_empty_file(tmp_path):
    path = _write_yaml(tmp_path, "")
    with pytest.raises(PolicyLoadError, match="empty"):
        load_policy(path)


def test_load_unknown_rule_type(tmp_path):
    yaml_content = """\
version: "0.1"
policies:
  - name: bad-rule
    type: custom_rule
    tools: [foo]
"""
    path = _write_yaml(tmp_path, yaml_content)
    with pytest.raises(PolicyLoadError, match="validation failed"):
        load_policy(path)


def test_load_unknown_detector(tmp_path):
    yaml_content = """\
version: "0.1"
detectors:
  nosql_injection: true
"""
    path = _write_yaml(tmp_path, yaml_content)
    with pytest.raises(PolicyLoadError, match="validation failed"):
        load_policy(path)


def test_load_missing_required_field(tmp_path):
    yaml_content = """\
version: "0.1"
policies:
  - name: incomplete
    type: tool_allow
"""
    path = _write_yaml(tmp_path, yaml_content)
    with pytest.raises(PolicyLoadError, match="validation failed"):
        load_policy(path)


# --- compile_regexes tests ---


def test_compile_regexes_valid():
    config = PolicyConfig(
        version="0.1",
        policies=[
            ParamRule(
                name="email-check",
                type="param_rule",
                match=ParamMatch(tool="send_email"),
                check=ParamCheck(
                    param="to",
                    op="matches",
                    value=r".*@mycompany\.com$",
                ),
            ),
            ChainRule(
                name="block-exfil",
                type="chain_rule",
                steps=[
                    ChainStep(
                        tool="read_file",
                        output_matches=r"BEGIN.*PRIVATE KEY",
                    ),
                    ChainStep(
                        tool="send_email",
                        param_matches={"to": r"^(?!.*@mycompany\.com$).*$"},
                    ),
                ],
            ),
        ],
    )

    compiled = compile_regexes(config)

    assert isinstance(compiled, CompiledPolicy)
    assert compiled.config is config
    assert len(compiled.regexes) == 3

    assert "email-check:check.value" in compiled.regexes
    assert "block-exfil:steps.0.output_matches" in compiled.regexes
    assert "block-exfil:steps.1.param_matches.to" in compiled.regexes

    for pattern in compiled.regexes.values():
        assert isinstance(pattern, re.Pattern)

    # Verify a pattern actually matches
    assert compiled.regexes["email-check:check.value"].search("user@mycompany.com")


def test_compile_regexes_invalid_pattern():
    config = PolicyConfig(
        version="0.1",
        policies=[
            ParamRule(
                name="bad-regex",
                type="param_rule",
                match=ParamMatch(tool="test_tool"),
                check=ParamCheck(
                    param="arg",
                    op="matches",
                    value="[invalid(regex",
                ),
            ),
        ],
    )

    with pytest.raises(PolicyLoadError, match="bad-regex"):
        compile_regexes(config)
