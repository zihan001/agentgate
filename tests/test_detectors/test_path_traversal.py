"""Tests for path traversal detector."""

from agentgate.detectors.path_traversal import detect
from agentgate.models import ToolCall


def _call(arguments: dict) -> ToolCall:
    """Build a ToolCall with the given arguments."""
    return ToolCall(tool_name="read_file", arguments=arguments, call_id=1)


# ── Positive cases (8) — must detect ────────────────────────────────────


def test_relative_traversal_etc_passwd():
    result = detect(_call({"path": "../../etc/passwd"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "traversal" in result.detail.lower()


def test_absolute_etc_shadow():
    result = detect(_call({"path": "/etc/shadow"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "/etc/" in result.detail


def test_tilde_ssh_key():
    result = detect(_call({"path": "~/.ssh/id_rsa"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "~/.ssh" in result.detail


def test_traversal_from_allowed_dir():
    result = detect(_call({"path": "/data/workspace/../../../etc/passwd"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "traversal" in result.detail.lower()


def test_proc_self_environ():
    result = detect(_call({"path": "/proc/self/environ"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "/proc/" in result.detail


def test_url_encoded_traversal():
    result = detect(_call({"path": "%2e%2e%2f%2e%2e%2fetc/passwd"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "traversal" in result.detail.lower()


def test_null_byte_injection():
    result = detect(_call({"path": "/data/workspace/safe%00../../etc/passwd"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "null byte" in result.detail.lower() or "traversal" in result.detail.lower()


def test_home_user_ssh():
    result = detect(_call({"path": "/home/ubuntu/.ssh/authorized_keys"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "home" in result.detail.lower()


# ── Negative cases (7) — must NOT detect ────────────────────────────────


def test_safe_absolute_path():
    result = detect(_call({"path": "/data/workspace/reports/q4.csv"}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_safe_relative_path():
    result = detect(_call({"path": "./local_file.txt"}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_slash_in_non_traversal_context():
    result = detect(_call({"body": "profits grew quarter/quarter"}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_safe_nested_dir():
    result = detect(_call({"path": "/data/workspace/etc/report.csv"}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_no_string_params():
    result = detect(_call({"recursive": True, "depth": 3}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_empty_arguments():
    result = detect(_call({}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


def test_safe_absolute_path_deep():
    result = detect(_call({"path": "/data/workspace/subdir/another/file.md"}))
    assert result.matched is False
    assert result.detector_name == "path_traversal"


# ── Edge cases (2) ──────────────────────────────────────────────────────


def test_nested_arg_traversal():
    result = detect(_call({"options": {"backup_path": "../../tmp/backup"}}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "options.backup_path" in result.detail


def test_windows_backslash_traversal():
    result = detect(_call({"path": "..\\..\\windows\\system32\\config\\sam"}))
    assert result.matched is True
    assert result.detector_name == "path_traversal"
    assert "traversal" in result.detail.lower()
